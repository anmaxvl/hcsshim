package hvsocket

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/Microsoft/go-winio/pkg/guid"
	"golang.org/x/sys/windows"
)

func HCSIDToGUID(id string) (guid.GUID, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, utf16.Encode([]rune(strings.ToUpper(id)))); err != nil {
		return guid.GUID{}, err
	}
	g, err := guid.NewV5(guid.GUID{Data1: 0xcab70344, Data2: 0xfacb, Data3: 0x41e4, Data4: [8]byte{0xb5, 0xe5, 0xab, 0x65, 0x92, 0x28, 0x3e, 0x6e}}, buf.Bytes())
	if err != nil {
		return guid.GUID{}, err
	}
	return g, nil
}

const (
	cHVSOCKET_ADDRESS_FLAG_PASSTHRU     = 0x00000001
	cIOCTL_HVSOCKET_UPDATE_ADDRESS_INFO = 0x21c004
)

type tHVSOCKET_ADDRESS_INFO struct {
	SystemId         guid.GUID
	VirtualMachineId guid.GUID
	SiloId           guid.GUID
	Flags            uint32
}

type Handle windows.Handle

func (h Handle) Release(ctx context.Context) error {
	return windows.CloseHandle(windows.Handle(h))
}

func CreateAddressInfo(cid, vmid guid.GUID, passthru bool) (Handle, error) {
	path := fmt.Sprintf(`\\.\HvSocketSystem\AddressInfo\{%s}`, cid)
	u16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(
		u16,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_NEW,
		0,
		0,
	)
	if err != nil {
		return 0, err
	}

	addrInfo := tHVSOCKET_ADDRESS_INFO{
		SystemId:         cid,
		VirtualMachineId: vmid,
	}
	if passthru {
		addrInfo.Flags |= cHVSOCKET_ADDRESS_FLAG_PASSTHRU
	}

	var ret uint32
	if err := windows.DeviceIoControl(
		h,
		cIOCTL_HVSOCKET_UPDATE_ADDRESS_INFO,
		(*byte)(unsafe.Pointer(&addrInfo)),
		uint32(unsafe.Sizeof(addrInfo)),
		nil,
		0,
		&ret,
		nil,
	); err != nil {
		return 0, err
	}

	return Handle(h), nil
}
