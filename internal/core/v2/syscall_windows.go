package core

import (
	"bytes"
	"encoding/binary"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

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

func GetProcessID(name string) (uint32, error) {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	// 获取第一个进程信息
	err = windows.Process32First(handle, &pe)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	for {
		if windows.UTF16ToString(pe.ExeFile[:]) == name {
			return pe.ProcessID, nil
		}

		err = windows.Process32Next(handle, &pe)
		if err != nil {
			return 0, errors.WithStack(err)
		}
	}
}

func ExeFilename(handle windows.Handle) (string, error) {
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(syscall.MAX_LONG_PATH)
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", errors.WithStack(err)
	}
	return windows.UTF16ToString(buf), nil
}

func GetBits(process windows.Handle) (int, error) {
	info := &systemInfo{}
	if err := GetNativeSystemInfo(info); err != nil {
		return 0, errors.WithStack(err)
	}

	var is64BitOS bool
	if info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 {
		is64BitOS = true
	}

	var isWow64 bool
	if err := windows.IsWow64Process(process, &isWow64); err != nil {
		return 0, errors.WithStack(err)
	}

	if is64BitOS {
		if isWow64 {
			return 32, nil // 32位进程在64位操作系统上运行
		}
		return 64, nil // 64位进程在64位操作系统上运行
	}
	return 32, nil // 32位操作系统
}

func EnumProcessModules(process windows.Handle) ([]windows.Handle, error) {
	handleSize := unsafe.Sizeof(process)

	moduleSize := uint32(1024)
	for {
		hMods := make([]windows.Handle, moduleSize)
		var cbNeeded uint32
		err := windows.EnumProcessModules(process, &hMods[0], uint32(handleSize)*moduleSize, &cbNeeded)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		count := cbNeeded / uint32(handleSize)
		if count <= moduleSize {
			return hMods[:count], nil
		}
		moduleSize = count
	}
}

func GetModuleFileNameEx(process windows.Handle, module windows.Handle) (string, error) {
	var modName [windows.MAX_PATH]uint16
	if err := windows.GetModuleFileNameEx(process, module, &modName[0], uint32(len(modName))); err != nil {
		return "", errors.WithStack(err)
	}
	return windows.UTF16ToString(modName[:]), nil
}

func GetModuleInformation(process windows.Handle, module windows.Handle) (windows.ModuleInfo, error) {
	var modInfo windows.ModuleInfo
	if err := windows.GetModuleInformation(process, module, &modInfo, uint32(unsafe.Sizeof(modInfo))); err != nil {
		return windows.ModuleInfo{}, errors.WithStack(err)
	}
	return modInfo, nil
}

func ReadMemory(process windows.Handle, address uintptr, buffer []byte) (uintptr, error) {
	var bytesRead uintptr
	err := windows.ReadProcessMemory(process, address, &buffer[0], uintptr(len(buffer)), &bytesRead)
	if err != nil {
		if err == windows.ERROR_PARTIAL_COPY {
			// 读取部分内存成功，返回已读取的字节数
			return bytesRead, nil
		}
		return 0, errors.WithStack(err)
	}
	return bytesRead, nil
}

type ScanMemoryOptions struct {
	ModuleName string
	Limit      int
}

func DefaultScanMemoryOptions() ScanMemoryOptions {
	return ScanMemoryOptions{
		ModuleName: "",
		Limit:      100,
	}
}

func ScanMemory(process windows.Handle, target any) ([]uintptr, error) {
	return ScanMemoryWithOptions(process, target, DefaultScanMemoryOptions())
}

func ScanMemoryWithOptions(process windows.Handle, target any, options ScanMemoryOptions) ([]uintptr, error) {
	if options.Limit <= 0 {
		return nil, errors.Errorf("limit must be greater than 0")
	}

	bits, err := GetBits(process)
	if err != nil {
		return nil, err
	}

	var startAddr uintptr
	var endAddr uintptr = 0x00007FFFFFFFFFFF // 64位地址空间的最大值
	if options.ModuleName != "" {
		hMods, err := EnumProcessModules(process)
		if err != nil {
			return nil, err
		}
		for _, hMod := range hMods {
			name, err := GetModuleFileNameEx(process, hMod)
			if err != nil {
				return nil, err
			}
			if strings.Contains(name, options.ModuleName) {
				modInfo, err := GetModuleInformation(process, hMod)
				if err != nil {
					return nil, err
				}
				startAddr = uintptr(hMod)
				endAddr = startAddr + uintptr(modInfo.SizeOfImage)
				break
			}
		}
	}

	var res []uintptr
	for {
		if startAddr >= endAddr {
			break
		}

		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(process, startAddr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}

		results, err := findInMemory(process, bits, mbi, target)
		if err != nil {
			return nil, err
		}
		for _, v := range results {
			res = append(res, mbi.BaseAddress+v)
		}
		if len(res) >= options.Limit {
			break
		}

		startAddr = mbi.BaseAddress + mbi.RegionSize
	}

	return res, nil
}

func findInMemory(process windows.Handle, bits int, mbi windows.MemoryBasicInformation, target any) ([]uintptr, error) {
	if mbi.State != windows.MEM_COMMIT {
		return nil, nil
	}
	if mbi.Protect&(windows.PAGE_READONLY|windows.PAGE_READWRITE|windows.PAGE_EXECUTE_READ|windows.PAGE_EXECUTE_READWRITE) == 0 {
		return nil, nil
	}
	if mbi.RegionSize >= 2*(1<<30) {
		return nil, nil
	}
	buffer := make([]byte, mbi.RegionSize)
	bytesRead, err := ReadMemory(process, mbi.BaseAddress, buffer)
	if err != nil {
		return nil, err
	}
	return find(bits, buffer[:bytesRead], target)
}

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
		default:
			return nil, errors.Errorf("unsupported bits: %d", bits)
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
