package uvm

import (
	"context"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Microsoft/hcsshim/internal/guestrequest"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/requesttype"
	hcsschema "github.com/Microsoft/hcsshim/internal/schema2"
)

const (
	lcowVPMEMLayerFmt        = "/run/layers/p%d"
	lcowVPMEMStackedLayerFmt = "/run/layers/p%d-%d-%d"
	PageSize                 = 0x1000
)

var (
	// ErrMaxVPMEMLayerSize is the error returned when the size of `hostPath` is
	// greater than the max vPMEM layer size set at create time.
	ErrMaxVPMEMLayerSize = errors.New("layer size is to large for VPMEM max size")
	ErrNotEnoughSpace    = errors.New("not enough space")
)

type slotDescriptor struct {
	deviceNumber uint32
	slotPosition int
	deviceOffset uint64
	deviceSize   uint64
}

// findNextVPMEM finds the next available VPMem slot.
//
// The lock MUST be held when calling this function.
func (uvm *UtilityVM) findNextVPMEM(ctx context.Context, hostPath string) (*slotDescriptor, error) {
	fi, err := os.Stat(hostPath)
	if err != nil {
		return nil, err
	}

	devSize := uint64(fi.Size())
	if devSize%PageSize != 0 {
		devSize = (devSize/PageSize + 1) * PageSize
	}

	for i := uint32(0); i < uvm.vpmemMaxCount; i++ {
		vi := uvm.mappedVPMemDevices[i]
		sd := &slotDescriptor{
			deviceNumber: i,
			slotPosition: 0,
			deviceOffset: 0,
			deviceSize:   devSize,
		}
		// Return first available slot
		if vi == nil {
			return sd, nil
		}

		slot, offset, err := vi.findNextMappingSlot(ctx, devSize)
		if err == nil {
			sd.slotPosition = slot
			sd.deviceOffset = offset
			return sd, nil
		}
		if err != ErrNotEnoughSpace {
			return nil, err
		}
	}

	return nil, ErrNoAvailableLocation
}

// findNextMappingSlot checks if a device with `devSize` can fit on the VPMEM
func (vpd *vpmemDevice) findNextMappingSlot(ctx context.Context, devSize uint64) (slot int, offset uint64, err error) {
	// Check if the new device can fit
	if len(vpd.mappings) > 0 {
		// Check if the new device fits at position 0
		if vpd.mappings[0].deviceOffset >= devSize {
			return 0, 0, nil
		}
	}

	// Check if new device fits at an intermediate position `j`
	for j := 1; j < len(vpd.mappings); j++ {
		newOffset := vpd.mappings[j-1].deviceOffset + vpd.mappings[j-1].deviceSize
		if vpd.mappings[j].deviceOffset-newOffset >= devSize {
			return j, newOffset, nil
		}
	}

	// Check if new device fits at the end
	lastSlot := vpd.mappings[len(vpd.mappings)-1]
	newOffset := lastSlot.deviceOffset + lastSlot.deviceSize
	if vpd.maxSize-newOffset >= devSize {
		return len(vpd.mappings), newOffset, nil
	}
	return 0, 0, ErrNotEnoughSpace
}

func (vpd *vpmemDevice) AddMapping(ctx context.Context, sd *slotDescriptor, hostPath string) (mapping *vpmemMapping, err error) {
	if sd.slotPosition < 0 || sd.slotPosition > len(vpd.mappings) {
		return nil, errors.New("invalid slot position")
	}
	mapping = &vpmemMapping{
		hostPath:     hostPath,
		deviceSize:   sd.deviceSize,
		deviceOffset: sd.deviceOffset,
		refCount:     1,
		uvmPath:      fmt.Sprintf(lcowVPMEMStackedLayerFmt, sd.deviceNumber, sd.deviceOffset, sd.deviceSize),
	}

	vpd.mappings = append(vpd.mappings, nil)
	copy(vpd.mappings[(sd.slotPosition+1):], vpd.mappings[sd.slotPosition:])
	vpd.mappings[sd.slotPosition] = mapping
	defer func() {
		if err != nil {
			// shift back and get rid of last element
			innerErr := vpd.RemoveMapping(ctx, sd, hostPath)
			if innerErr != nil {
				log.G(ctx).Debugf("could not remove mapping: %s", innerErr)
			}
		}
	}()

	// check integrity
	for i := 0; i < len(vpd.mappings)-1; i++ {
		current := vpd.mappings[i]
		next := vpd.mappings[i+1]
		if next.deviceOffset-current.deviceOffset < current.deviceSize {
			return nil, errors.New("new mapping overlaps with existing ones")
		}
	}
	last := vpd.mappings[len(vpd.mappings)-1]
	if vpd.maxSize-last.deviceOffset < last.deviceSize {
		return nil, errors.New("new mapping doesn't fit on the device")
	}
	return mapping, nil
}

func (vpd *vpmemDevice) RemoveMapping(ctx context.Context, sd *slotDescriptor, hostPath string) error {
	mapping := vpd.mappings[sd.slotPosition]
	if mapping.hostPath != hostPath {
		return errors.New("hostPaths don't match")
	}

	mapping.refCount--
	if mapping.refCount < 1 {
		log.G(ctx).WithFields(logrus.Fields{
			"hostPath":     hostPath,
			"deviceNumber": sd.deviceNumber,
			"deviceOffset": sd.deviceOffset,
			"deviceSize":   sd.deviceSize,
		}).Debug("removing mapping from VPMEM")
		copy(vpd.mappings[sd.slotPosition:], vpd.mappings[(sd.slotPosition+1):])
		vpd.mappings = vpd.mappings[:len(vpd.mappings)-1]
	}
	return nil
}

// findVPMEMDevice finds an existing device mapped on a VPMEM
//
// Lock must be held when calling this function
func (uvm *UtilityVM) findVPMEMDevice(ctx context.Context, findThisHostPath string) (*slotDescriptor, error) {
	for i := uint32(0); i < uvm.vpmemMaxCount; i++ {
		vi := uvm.mappedVPMemDevices[i]
		if vi == nil {
			continue
		}

		for pos, mapping := range vi.mappings {
			if mapping.hostPath == findThisHostPath {
				log.G(ctx).WithFields(logrus.Fields{
					"deviceNumber":    i,
					"hostPath":        mapping.hostPath,
					"uvmPath":         mapping.uvmPath,
					"mappingPosition": pos,
					"refCount":        mapping.refCount,
					"mappingOffset":   mapping.deviceOffset,
					"mappingSize":     mapping.deviceSize,
				})
			}
			return &slotDescriptor{
				deviceNumber: i,
				slotPosition: pos,
			}, nil
		}
	}
	return nil, ErrNotAttached
}

// AddVPMEM adds a VPMEM disk to a utility VM at the next available location and
// returns the UVM path where the layer was mounted.
func (uvm *UtilityVM) AddVPMEM(ctx context.Context, hostPath string) (_ string, err error) {
	if uvm.operatingSystem != "linux" {
		return "", errNotSupported
	}

	uvm.m.Lock()
	defer uvm.m.Unlock()

	var sd *slotDescriptor
	sd, err = uvm.findVPMEMDevice(ctx, hostPath)
	if err != nil {
		// We are going to add it so make sure it fits on vPMEM
		fi, err := os.Stat(hostPath)
		if err != nil {
			return "", err
		}
		if uint64(fi.Size()) > uvm.vpmemMaxSizeBytes {
			return "", ErrMaxVPMEMLayerSize
		}

		// It doesn't exist, so we're going to allocate and hot-add it
		sd, err = uvm.findNextVPMEM(ctx, hostPath)
		if err != nil {
			return "", err
		}

		modification := &hcsschema.ModifySettingRequest{
			RequestType: requesttype.Add,
		}

		device := uvm.mappedVPMemDevices[sd.deviceNumber]
		if device == nil {
			device = &vpmemDevice{
				maxSize: uvm.vpmemMaxSizeBytes,
			}
		}

		if len(device.mappings) == 0 {
			// New device with no mappings assigned yet
			modification.Settings = hcsschema.VirtualPMemDevice{
				ReadOnly:    true,
				HostPath:    hostPath,
				ImageFormat: "Vhd1",
			}
			modification.ResourcePath = fmt.Sprintf(vPMemControllerResourceFormat, sd.deviceNumber)
		} else {
			// VPMEM device already exists, modify mapped devices
			modification.Settings = hcsschema.VirtualPMemMapping{
				HostPath:    hostPath,
				ImageFormat: "Vhd1",
			}
			modification.ResourcePath = fmt.Sprintf(vPMemDeviceResourceFormat, sd.deviceNumber, sd.deviceOffset)
		}

		uvmPath := fmt.Sprintf(lcowVPMEMStackedLayerFmt, sd.deviceNumber, sd.deviceOffset, sd.deviceSize)
		modification.GuestRequest = guestrequest.GuestRequest{
			ResourceType: guestrequest.ResourceTypeVPMemDevice,
			RequestType:  requesttype.Add,
			Settings: guestrequest.LCOWMappedVPMemDevice{
				DeviceNumber: sd.deviceNumber,
				Mapping: guestrequest.LCOWMappedLayer{
					MountPath:           uvmPath,
					DeviceOffsetInBytes: sd.deviceOffset,
					DeviceSizeInBytes:   sd.deviceSize,
				},
			},
		}

		if err := uvm.modify(ctx, modification); err != nil {
			return "", fmt.Errorf("uvm::AddVPMEM: failed to modify utility VM configuration: %s", err)
		}

		var mapping *vpmemMapping
		mapping, err = device.AddMapping(ctx, sd, hostPath)
		if err != nil {
			return "", errors.Wrapf(err, "failed adding VirtualPMem layer: %s", hostPath)
		}

		return mapping.uvmPath, nil
	}
	mapping := uvm.mappedVPMemDevices[sd.deviceNumber].mappings[sd.slotPosition]
	mapping.refCount++
	return mapping.uvmPath, nil
}

// RemoveVPMEM removes a VPMEM disk from a Utility VM. If the `hostPath` is not
// attached returns `ErrNotAttached`.
func (uvm *UtilityVM) RemoveVPMEM(ctx context.Context, hostPath string) (err error) {
	if uvm.operatingSystem != "linux" {
		return errNotSupported
	}

	uvm.m.Lock()
	defer uvm.m.Unlock()

	slotDescriptor, err := uvm.findVPMEMDevice(ctx, hostPath)
	if err != nil {
		return err
	}

	device := uvm.mappedVPMemDevices[slotDescriptor.deviceNumber]
	mapping := device.mappings[slotDescriptor.slotPosition]
	if mapping.refCount == 1 {
		modification := &hcsschema.ModifySettingRequest{
			RequestType: requesttype.Remove,
		}
		if len(device.mappings) == 1 {
			// Host remove device
			modification.ResourcePath = fmt.Sprintf(vPMemControllerResourceFormat, slotDescriptor.deviceNumber)
		} else {
			// Host remove mapping
			modification.ResourcePath = fmt.Sprintf(vPMemDeviceResourceFormat, slotDescriptor.deviceNumber, slotDescriptor.deviceOffset)
		}
		// Guest doesn't care if device is removed or not, just remove the mapping and block device
		modification.GuestRequest = guestrequest.GuestRequest{
			ResourceType: guestrequest.ResourceTypeVPMemDevice,
			RequestType:  requesttype.Remove,
			Settings: guestrequest.LCOWMappedVPMemDevice{
				DeviceNumber: slotDescriptor.deviceNumber,
				MountPath:    mapping.uvmPath,
			},
		}
		if err := uvm.modify(ctx, modification); err != nil {
			return errors.Errorf("failed to remove VPMEM %s from utility VM %s: %s", hostPath, uvm.id, err)
		}
		log.G(ctx).WithFields(logrus.Fields{
			"hostPath":     mapping.hostPath,
			"uvmPath":      mapping.uvmPath,
			"refCount":     mapping.refCount,
			"deviceNumber": slotDescriptor.deviceNumber,
		}).Debug("removed VPMEM location")

		err := device.RemoveMapping(ctx, slotDescriptor, hostPath)
		if err != nil {
			return errors.Wrapf(err, "failed to remove VPMEM mapping")
		}
		// remove device if no mappings
		if len(device.mappings) == 0 {
			uvm.mappedVPMemDevices[slotDescriptor.deviceNumber] = nil
		}
		return nil
	}
	return device.RemoveMapping(ctx, slotDescriptor, hostPath)
}
