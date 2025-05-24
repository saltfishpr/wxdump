package core

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func GetWeChatVersion(processID uint32) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processID)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer windows.CloseHandle(process) //nolint

	execPath, err := GetModuleFileNameEx(process, 0)
	if err != nil {
		return "", err
	}
	version, err := GetFileVersionInfo(execPath)
	if err != nil {
		return "", err
	}
	return version, nil
}

func ScanWXIDFromMemory(processID uint32) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer windows.CloseHandle(process) //nolint

	addrs, err := ScanMemory(process, "\\Msg\\FTSContact")
	if err != nil {
		return "", err
	}

	if len(addrs) == 0 {
		return "", errors.New("no wxid found")
	}

	var ids []string
	for _, addr := range addrs {
		s, err := ReadStringFromMemory(process, addr-30, 80)
		if err != nil {
			return "", err
		}
		if idx := strings.Index(s, "\\Msg"); idx >= 0 {
			s = s[:idx]
		}
		id, ok := lo.Last(strings.Split(s, "\\"))
		if ok {
			ids = append(ids, id)
		}
	}

	counts := lo.CountValues(ids)
	var res string
	var maxCount int
	for id, count := range counts {
		if count > maxCount {
			res = id
			maxCount = count
		}
	}
	return res, nil
}

func GetWXDirFromReg() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Tencent\WeChat`, registry.QUERY_VALUE)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer k.Close()

	s, _, err := k.GetStringValue("FileSavePath")
	if err != nil {
		return "", errors.WithStack(err)
	}

	res := s

	if s == "MyDocument:" {
		k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, registry.QUERY_VALUE)
		if err != nil {
			return "", errors.WithStack(err)
		}
		defer k.Close()
		// "Personal" 是 "MyDocument:" 对应的键名
		docPath, _, err := k.GetStringValue("Personal")
		if err != nil {
			return "", errors.WithStack(err)
		}
		expandedPath, err := registry.ExpandString(docPath)
		if err != nil {
			return "", errors.WithStack(err)
		}
		res = expandedPath
	}

	return filepath.Join(res, "WeChat Files"), nil
}

type CrackDatabaseKeyOptions struct {
	Account string
}

// CrackDatabaseKey 爆破数据库密钥
func CrackDatabaseKey(processID uint32, dbFilename string, options CrackDatabaseKeyOptions) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer windows.CloseHandle(process) //nolint

	info := &systemInfo{}
	if err := GetNativeSystemInfo(info); err != nil {
		return "", errors.WithStack(err)
	}

	bits, err := GetBits(process)
	if err != nil {
		return "", err
	}
	pSize := uintptr(bits / 8)

	ranges, err := getPossibleAddressRange(process, options)
	if err != nil {
		return "", err
	}

	fileBuf, err := os.ReadFile(dbFilename)
	if err != nil {
		return "", errors.WithStack(err)
	}

	for _, r := range ranges {
		startAddr := r[0]
		endAddr := r[1]

		// 对齐地址
		if startAddr%pSize != 0 {
			startAddr -= startAddr % pSize
		}
		if endAddr%pSize != 0 {
			endAddr += pSize - endAddr%pSize
		}

		log.Info("scan memory", "start", fmt.Sprintf("0x%x", startAddr), "end", fmt.Sprintf("0x%x", endAddr))

		for addr := startAddr; addr < endAddr; addr += pSize {
			if addr < info.lpMinimumApplicationAddress || addr > info.lpMaximumApplicationAddress {
				continue
			}

			key, err := readKeyFromMemory(process, addr)
			if err != nil {
				continue
			}
			// 尝试解密数据库
			if err := DecryptDB(key, bytes.NewBuffer(fileBuf), io.Discard); err != nil {
				continue
			}
			return key, nil
		}
	}

	return "", errors.New("key not found")
}

func getPossibleAddressRange(process windows.Handle, options CrackDatabaseKeyOptions) ([][2]uintptr, error) {
	if options.Account != "" {
		addrs, err := ScanMemoryWithOptions(process, options.Account, ScanMemoryOptions{
			ModuleName: "WeChatWin.dll",
			Limit:      100,
		})
		if err != nil {
			return nil, err
		}
		var res [][2]uintptr
		for _, addr := range addrs {
			res = append(res, [2]uintptr{addr - 0x1000, addr + 0x1000}) // TODO: 支持配置
		}
		return res, nil
	}

	hMod, err := GetModuleByName(process, "WeChatWin.dll")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	modInfo, err := GetModuleInformation(process, hMod)
	if err != nil {
		return nil, err
	}
	startAddr := uintptr(hMod)
	endAddr := startAddr + uintptr(modInfo.SizeOfImage)
	return [][2]uintptr{{startAddr, endAddr}}, nil
}

func readKeyFromMemory(process windows.Handle, address uintptr) (string, error) {
	pointer, err := ReadPointerFromMemory(process, address)
	if err != nil {
		return "", errors.WithStack(err)
	}

	buf := make([]byte, KeySize)
	bytesRead, err := ReadMemory(process, pointer, buf)
	if err != nil {
		return "", err
	}
	if bytesRead != KeySize {
		return "", errors.New("read key size mismatch")
	}

	return fmt.Sprintf("%x", buf), nil
}
