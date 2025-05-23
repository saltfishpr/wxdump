package core

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	getNativeSystemInfo = modkernel32.NewProc("GetNativeSystemInfo")
)

const (
	PROCESSOR_ARCHITECTURE_AMD64 = 9  // x64 (AMD or Intel)
	PROCESSOR_ARCHITECTURE_ARM   = 5  // ARM
	PROCESSOR_ARCHITECTURE_ARM64 = 12 // ARM64
	PROCESSOR_ARCHITECTURE_IA64  = 6  // Intel Itanium
	PROCESSOR_ARCHITECTURE_INTEL = 0  // x86
)

type systemInfo struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

func GetNativeSystemInfo(info *systemInfo) error {
	_, _, err := getNativeSystemInfo.Call(uintptr(unsafe.Pointer(info)))
	if err == windows.NTE_OP_OK {
		return nil
	}
	return err
}
