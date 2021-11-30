package uvm

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/Microsoft/go-winio/pkg/security"
	"github.com/Microsoft/hcsshim/ext4/dmverity"
	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/pkg/errors"
)

// AddHashDevice adds a SCSI device to the UVM, which can be used by device-mapper for integrity checking.
func (uvm *UtilityVM) AddHashDevice(ctx context.Context, hashDevPath, layerPath string) (_ *SCSIMount, err error) {
	opts := []string{"ro"}
	scsiMount, addErr := uvm.AddSCSI(ctx, hashDevPath, "", true, false, opts, VMAccessTypeNoop)
	if addErr != nil {
		return nil, addErr
	}

	if _, ok := uvm.hashDevices[layerPath]; !ok {
		uvm.hashDevices[layerPath] = scsiMount
	}
	return scsiMount, nil
}

func (uvm *UtilityVM) RemoveHashDevice(ctx context.Context, hashDevPath, layerPath string) (err error) {
	if err := uvm.RemoveSCSI(ctx, hashDevPath); err != nil {
		return err
	}
	scsiMount, ok := uvm.hashDevices[layerPath]
	if !ok {
		return nil
	}
	if scsiMount.refCount > 0 {
		return nil
	}
	delete(uvm.hashDevices, layerPath)
	return nil
}

// CreateHashDevice computes and saves cryptographic digest of a given layer as a separate VHD, which
// can be presented to the UVM for integrity checking.
func (uvm *UtilityVM) CreateHashDevice(ctx context.Context, layerPath string) (hashDevPath string, err error) {
	dirPath := filepath.Dir(layerPath)
	hashDevPath = filepath.Join(dirPath, "hash-dev.vhd")
	if _, err := os.Stat(hashDevPath); err == nil {
		return hashDevPath, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	layerFile, err := os.Open(layerPath)
	if err != nil {
		return "", errors.Wrapf(err, "failed to open layer VHD for read: %s", layerPath)
	}
	defer layerFile.Close()

	tmpFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp file")
	}
	defer func() {
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()

	if err := dmverity.ComputeAndWriteHashDevice(layerFile, tmpFile); err != nil {
		return "", err
	}

	if err := tar2ext4.ConvertToVhd(tmpFile); err != nil {
		return "", err
	}

	if err := tmpFile.Sync(); err != nil {
		return "", errors.Wrap(err, "failed to flush to disk")
	}
	tmpFile.Close()

	if err := security.GrantVmGroupAccess(tmpFile.Name()); err != nil {
		return "", fmt.Errorf("failed to grant vm group access on hash device: %s", hashDevPath)
	}

	if _, err := os.Stat(hashDevPath); err == nil {
		return hashDevPath, nil
	}
	if err := os.Rename(tmpFile.Name(), hashDevPath); err != nil {
		return "", errors.Wrapf(err, "failed to rename hash device VHD")
	}
	log.G(ctx).WithField("hashDevPath", hashDevPath).Debug("created hash device")
	return
}

// readHashDevice checks if the hash-device has been appended to the layer VHD or if it was written
// as a separate VHD, returns hash device object.
func (uvm *UtilityVM) readHashDevice(ctx context.Context, layerPath string) (error, interface{}) {
	return nil, nil
}
