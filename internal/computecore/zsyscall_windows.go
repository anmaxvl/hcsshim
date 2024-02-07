//go:build windows

// Code generated by 'go generate' using "github.com/Microsoft/go-winio/tools/mkwinsyscall"; DO NOT EDIT.

package computecore

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modcomputecore = windows.NewLazySystemDLL("computecore.dll")

	procHcsAddResourceToOperation = modcomputecore.NewProc("HcsAddResourceToOperation")
	procHcsCloseOperation         = modcomputecore.NewProc("HcsCloseOperation")
	procHcsCreateComputeSystem    = modcomputecore.NewProc("HcsCreateComputeSystem")
	procHcsCreateOperation        = modcomputecore.NewProc("HcsCreateOperation")
	procHcsGetOperationId         = modcomputecore.NewProc("HcsGetOperationId")
	procHcsGetOperationResult     = modcomputecore.NewProc("HcsGetOperationResult")
	procHcsGetOperationType       = modcomputecore.NewProc("HcsGetOperationType")
	procHcsWaitForOperationResult = modcomputecore.NewProc("HcsWaitForOperationResult")
)

func hcsAddResourceToOperation(operation HCSOperation, rtype uint32, uri string, handle syscall.Handle) (hr error) {
	var _p0 *uint16
	_p0, hr = syscall.UTF16PtrFromString(uri)
	if hr != nil {
		return
	}
	return _hcsAddResourceToOperation(operation, rtype, _p0, handle)
}

func _hcsAddResourceToOperation(operation HCSOperation, rtype uint32, uri *uint16, handle syscall.Handle) (hr error) {
	hr = procHcsAddResourceToOperation.Find()
	if hr != nil {
		return
	}
	r0, _, _ := syscall.Syscall6(procHcsAddResourceToOperation.Addr(), 4, uintptr(operation), uintptr(rtype), uintptr(unsafe.Pointer(uri)), uintptr(handle), 0, 0)
	if int32(r0) < 0 {
		if r0&0x1fff0000 == 0x00070000 {
			r0 &= 0xffff
		}
		hr = syscall.Errno(r0)
	}
	return
}

func hcsCloseOperation(operation HCSOperation) (hr error) {
	hr = procHcsCloseOperation.Find()
	if hr != nil {
		return
	}
	r0, _, _ := syscall.Syscall(procHcsCloseOperation.Addr(), 1, uintptr(operation), 0, 0)
	if int32(r0) < 0 {
		if r0&0x1fff0000 == 0x00070000 {
			r0 &= 0xffff
		}
		hr = syscall.Errno(r0)
	}
	return
}

func hcsCreateComputeSystem(id string, configuration string, operation HCSOperation, security_descriptor *uint32, computeSystem *HCSSystem) (hr error) {
	var _p0 *uint16
	_p0, hr = syscall.UTF16PtrFromString(id)
	if hr != nil {
		return
	}
	var _p1 *uint16
	_p1, hr = syscall.UTF16PtrFromString(configuration)
	if hr != nil {
		return
	}
	return _hcsCreateComputeSystem(_p0, _p1, operation, security_descriptor, computeSystem)
}

func _hcsCreateComputeSystem(id *uint16, configuration *uint16, operation HCSOperation, security_descriptor *uint32, computeSystem *HCSSystem) (hr error) {
	hr = procHcsCreateComputeSystem.Find()
	if hr != nil {
		return
	}
	r0, _, _ := syscall.Syscall6(procHcsCreateComputeSystem.Addr(), 5, uintptr(unsafe.Pointer(id)), uintptr(unsafe.Pointer(configuration)), uintptr(operation), uintptr(unsafe.Pointer(security_descriptor)), uintptr(unsafe.Pointer(computeSystem)), 0)
	if int32(r0) < 0 {
		if r0&0x1fff0000 == 0x00070000 {
			r0 &= 0xffff
		}
		hr = syscall.Errno(r0)
	}
	return
}

func hcsCreateOperation(context uintptr, callback hcsOperationCompletionUintptr) (op HCSOperation, err error) {
	err = procHcsCreateOperation.Find()
	if err != nil {
		return
	}
	r0, _, e1 := syscall.Syscall(procHcsCreateOperation.Addr(), 2, uintptr(context), uintptr(callback), 0)
	op = HCSOperation(r0)
	if op == 0 {
		err = errnoErr(e1)
	}
	return
}

func hcsGetOperationId(operation HCSOperation) (id uint64, err error) {
	err = procHcsGetOperationId.Find()
	if err != nil {
		return
	}
	r0, _, e1 := syscall.Syscall(procHcsGetOperationId.Addr(), 1, uintptr(operation), 0, 0)
	id = uint64(r0)
	if id == 0 {
		err = errnoErr(e1)
	}
	return
}

func hcsGetOperationResult(operation HCSOperation, resultDocument **uint16) (hr error) {
	hr = procHcsGetOperationResult.Find()
	if hr != nil {
		return
	}
	r0, _, _ := syscall.Syscall(procHcsGetOperationResult.Addr(), 2, uintptr(operation), uintptr(unsafe.Pointer(resultDocument)), 0)
	if int32(r0) < 0 {
		if r0&0x1fff0000 == 0x00070000 {
			r0 &= 0xffff
		}
		hr = syscall.Errno(r0)
	}
	return
}

func hcsGetOperationType(operation HCSOperation) (t HCSOperationType, err error) {
	err = procHcsGetOperationType.Find()
	if err != nil {
		return
	}
	r0, _, e1 := syscall.Syscall(procHcsGetOperationType.Addr(), 1, uintptr(operation), 0, 0)
	t = HCSOperationType(r0)
	if t == 0 {
		err = errnoErr(e1)
	}
	return
}

func hcsWaitForOperationResult(operation HCSOperation, timeoutMs uint32, resultDocument **uint16) (hr error) {
	hr = procHcsWaitForOperationResult.Find()
	if hr != nil {
		return
	}
	r0, _, _ := syscall.Syscall(procHcsWaitForOperationResult.Addr(), 3, uintptr(operation), uintptr(timeoutMs), uintptr(unsafe.Pointer(resultDocument)))
	if int32(r0) < 0 {
		if r0&0x1fff0000 == 0x00070000 {
			r0 &= 0xffff
		}
		hr = syscall.Errno(r0)
	}
	return
}
