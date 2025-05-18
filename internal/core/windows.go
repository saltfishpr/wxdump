package core

import (
	"debug/pe"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

func GetPEBits(filename string) (int, error) {
	file, err := pe.Open(filename)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	defer file.Close()

	switch oh := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return 32, nil
	case *pe.OptionalHeader64:
		return 64, nil
	default:
		return 0, errors.Errorf("未知的 Optional Header 类型: %T", oh)
	}
}

type ProcessEntry struct {
	ProcessID       uint32
	ParentProcessID uint32
	ExeFile         string
}

func GetProcessList() ([]*ProcessEntry, error) {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	// 获取第一个进程信息
	err = windows.Process32First(handle, &pe)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var processList []*ProcessEntry
	// 遍历所有进程
	for {
		processList = append(processList, &ProcessEntry{
			ProcessID:       pe.ProcessID,
			ParentProcessID: pe.ParentProcessID,
			ExeFile:         windows.UTF16ToString(pe.ExeFile[:]),
		})

		err = windows.Process32Next(handle, &pe)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break // 没有更多进程
			}
			return nil, errors.WithStack(err)
		}
	}

	return processList, nil
}

func GetProcessExePath(processID uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processID)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	buf := make([]uint16, windows.MAX_PATH)
	if err := windows.GetModuleFileNameEx(handle, 0, &buf[0], uint32(len(buf))); err != nil {
		return "", errors.WithStack(err)
	}

	return windows.UTF16ToString(buf[:]), nil
}

func GetFileVersionInfo(filename string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(filename, nil)
	if err != nil {
		return "", errors.WithStack(err)
	}

	data := make([]byte, size)
	err = windows.GetFileVersionInfo(filename, 0, size, unsafe.Pointer(&data[0]))
	if err != nil {
		return "", errors.WithStack(err)
	}

	var fixedInfo *windows.VS_FIXEDFILEINFO
	var uLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&data[0]), "\\", unsafe.Pointer(&fixedInfo), &uLen); err != nil {
		return "", errors.WithStack(err)
	}

	if fixedInfo.Signature != 0xFEEF04BD {
		return "", errors.Errorf("invalid file signature: 0x%X", fixedInfo.Signature)
	}

	version := fmt.Sprintf("%d.%d.%d.%d",
		(fixedInfo.FileVersionMS>>16)&0xffff,
		fixedInfo.FileVersionMS&0xffff,
		(fixedInfo.FileVersionLS>>16)&0xffff,
		fixedInfo.FileVersionLS&0xffff,
	)

	return version, nil
}

type MemoryInformation struct {
	BaseAddress uintptr
	RegionSize  uintptr
	Filename    string
}

func GetMemoryInformation(process windows.Handle) ([]*MemoryInformation, error) {
	var memInfo []*MemoryInformation
	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(process, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}

		var filename string
		mappedFileName := make([]uint16, windows.MAX_PATH)
		r1, _, _ := getMappedFileNameW.Call(
			uintptr(process),
			mbi.BaseAddress,
			uintptr(unsafe.Pointer(&mappedFileName[0])),
			uintptr(len(mappedFileName)),
		)
		if r1 != 0 {
			filename = windows.UTF16ToString(mappedFileName)
		}

		memInfo = append(memInfo, &MemoryInformation{
			BaseAddress: mbi.BaseAddress,
			RegionSize:  mbi.RegionSize,
			Filename:    filename,
		})

		// 移动到下一个内存区域
		addr = mbi.BaseAddress + mbi.RegionSize
	}

	return memInfo, nil
}

func ReadStringFromMemory(process windows.Handle, address uintptr, size int) (string, error) {
	buf := make([]byte, size)
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(process, address, &buf[0], uintptr(size), &bytesRead); err != nil {
		return "", errors.WithStack(err)
	}
	var builder strings.Builder
	for i := 0; i < int(bytesRead); i++ {
		if buf[i] == 0 {
			break
		}
		builder.WriteByte(buf[i])
	}
	return builder.String(), nil
}

func SearchInMemory(process windows.Handle, expr string, limit int) ([]uintptr, error) {
	allowedProtections := []uint32{
		windows.PAGE_EXECUTE,
		windows.PAGE_EXECUTE_READ,
		windows.PAGE_EXECUTE_READWRITE,
		windows.PAGE_READWRITE,
		windows.PAGE_READONLY,
	}
	re, err := regexp.Compile(regexp.QuoteMeta(expr))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var res []uintptr
	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(process, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}

		if mbi.State == windows.MEM_COMMIT && slices.Contains(allowedProtections, mbi.Protect) {
			regionBytes := make([]byte, mbi.RegionSize)
			var bytesRead uintptr
			if err := windows.ReadProcessMemory(process, mbi.BaseAddress, &regionBytes[0], uintptr(mbi.RegionSize), &bytesRead); err != nil {
				return nil, errors.WithStack(err)
			}
			matches := re.FindAllIndex(regionBytes, -1)
			for _, match := range matches {
				res = append(res, mbi.BaseAddress+uintptr(match[0]))
			}
		}
		if len(res) >= limit {
			break
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}

	return res, nil
}
