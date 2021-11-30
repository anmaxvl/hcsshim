package protocol

import (
	"encoding/json"
	"fmt"
)

// HashDeviceType is a type of hash device being presented to the guest.
type HashDeviceType string

const (
	// HashDeviceSCSI is a hash device presented as a SCSI device
	HashDeviceSCSI = HashDeviceType("HashDeviceSCSI")
	// HashDeviceVPMem is a hash device presented as a single VPMem device
	HashDeviceVPMem = HashDeviceType("HashDeviceVPMem")
	// HashDeviceMappedVPMem is a hash device presented as a mapped VPMem device
	HashDeviceMappedVPMem = HashDeviceType("HashDeviceMappedVPMem")
)

// DeviceVerityInfo represents dm-verity information of a given data device.
// The assumption is that the hash device is the same as data device with
// verity data appended in the end.
type DeviceVerityInfo struct {
	DevicePath      string
	Ext4SizeInBytes int64
	Version         int
	Algorithm       string
	SuperBlock      bool
	RootDigest      string
	Salt            string
	BlockSize       int
}

// HashDevice represents a block device and all the necessary verity information
// to be used for integrity checking. DeviceDescriptor references another block
// device exposed to the guest and can be a MappedVirtualDiskV2 or a MappedVPMemDeviceV2.
type HashDevice struct {
	DeviceType       HashDeviceType    `json:",omitempty"`
	DeviceVerityInfo *DeviceVerityInfo `json:",omitempty"`
	DeviceDescriptor interface{}       `json:",omitempty"`
}

func (hd *HashDevice) UnmarshalJSON(b []byte) error {
	type local struct {
		DeviceType       HashDeviceType
		DeviceVerityInfo *DeviceVerityInfo
		DeviceDescriptor *json.RawMessage
	}

	var l local
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	hd.DeviceType = l.DeviceType
	hd.DeviceVerityInfo = l.DeviceVerityInfo

	switch hd.DeviceType {
	case HashDeviceSCSI:
		var hds MappedVirtualDiskV2
		if err := json.Unmarshal(*l.DeviceDescriptor, &hds); err != nil {
			return err
		}
		hd.DeviceDescriptor = &hds
	case HashDeviceVPMem, HashDeviceMappedVPMem:
		var hdv MappedVPMemDeviceV2
		if err := json.Unmarshal(*l.DeviceDescriptor, &hdv); err != nil {
			return err
		}
		hd.DeviceDescriptor = &hdv
	default:
		return fmt.Errorf("invalid hadh device type: %s", hd.DeviceType)
	}
	return nil
}

// MappedVirtualDiskV2 represents a disk on the host which is mapped into a
// directory in the guest in the V2 schema.
type MappedVirtualDiskV2 struct {
	MountPath  string      `json:",omitempty"`
	Lun        uint8       `json:",omitempty"`
	Controller uint8       `json:",omitempty"`
	ReadOnly   bool        `json:",omitempty"`
	Encrypted  bool        `json:",omitempty"`
	Options    []string    `json:",omitempty"`
	HashDevice *HashDevice `json:",omitempty"`
}

// DeviceMappingInfo represents a mapped device on a given VPMem
type DeviceMappingInfo struct {
	DeviceOffsetInBytes int64 `json:",omitempty"`
	DeviceSizeInBytes   int64 `json:",omitempty"`
}

// MappedVPMemDeviceV2 represents a VPMem device that is mapped into a guest
// path in the V2 schema.
type MappedVPMemDeviceV2 struct {
	DeviceNumber uint32 `json:",omitempty"`
	MountPath    string `json:",omitempty"`
	// MappingInfo is used when multiple devices are mapped onto a single VPMem device
	MappingInfo *DeviceMappingInfo `json:",omitempty"`
	HashDevice  *HashDevice        `json:",omitempty"`
}
