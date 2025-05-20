package core

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/charmbracelet/log"
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
		return 0, errors.Errorf("unknown Optional Header type: %T", oh)
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

func GetProcessExePathWithPID(processID uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processID)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	return GetProcessExePath(handle)
}

func GetProcessExePath(process windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	if err := windows.GetModuleFileNameEx(process, 0, &buf[0], uint32(len(buf))); err != nil {
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
		if err != windows.ERROR_PARTIAL_COPY {
			return "", errors.WithStack(err)
		}
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

func SearchInMemory(process windows.Handle, target any, limit int) ([]uintptr, error) {
	execPath, err := GetProcessExePath(process)
	if err != nil {
		return nil, err
	}
	execBits, err := GetPEBits(execPath)
	if err != nil {
		return nil, err
	}

	var res []uintptr
	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(process, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		// TODO 不确定是否有问题，比如增加判断 RegionSize 不能超过 2G?
		if mbi.State == windows.MEM_COMMIT && mbi.Protect&(windows.PAGE_READWRITE|windows.PAGE_READONLY) != 0 {
			buffer := make([]byte, mbi.RegionSize)
			var bytesRead uintptr
			if err := windows.ReadProcessMemory(process, mbi.BaseAddress, &buffer[0], uintptr(mbi.RegionSize), &bytesRead); err != nil {
				if err != windows.ERROR_PARTIAL_COPY {
					return nil, errors.WithStack(err)
				} else {
					log.Debugf("BaseAddress: 0x%X, RegionSize: %d", mbi.BaseAddress, mbi.RegionSize) // TODO 这种情况暂时不知道如何处理，不影响使用
				}
			}
			results, err := find(execBits, buffer[:bytesRead], target)
			if err != nil {
				return nil, err
			}
			for _, v := range results {
				res = append(res, mbi.BaseAddress+v)
			}
		}
		if len(res) >= limit {
			break
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}

	return res, nil
}

// find 在 windows 内存 buffer 中寻找匹配所有 target 值的偏移量。根据 target 类型有不同实现
func find(bits int, buffer []byte, target any) ([]uintptr, error) {
	var pattern []byte

	switch v := target.(type) {
	case int:
		switch bits {
		case 64:
			pattern = make([]byte, 8)
			binary.LittleEndian.PutUint64(pattern, uint64(v))
		case 32:
			pattern = make([]byte, 4)
			binary.LittleEndian.PutUint32(pattern, uint32(v))
		}
	case int32:
		pattern = make([]byte, 4)
		binary.LittleEndian.PutUint32(pattern, uint32(v))
	case int64:
		pattern = make([]byte, 8)
		binary.LittleEndian.PutUint64(pattern, uint64(v))
	case string:
		pattern = []byte(v)
	case []byte:
		pattern = v
	default:
		return nil, errors.Errorf("unsupported type: %T", target)
	}

	patternLen := len(pattern)
	if patternLen == 0 {
		return nil, errors.Errorf("pattern is empty")
	}

	var results []uintptr

	offset := 0
	for {
		idx := bytes.Index(buffer[offset:], pattern)
		if idx == -1 {
			break // 没有找到更多匹配项
		}
		// 将相对索引转换为绝对偏移量
		results = append(results, uintptr(offset+idx))
		// 更新搜索的起始位置，避免重复匹配
		offset += idx + patternLen
	}

	return results, nil
}
