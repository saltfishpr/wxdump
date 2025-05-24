package core

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func GetWeChatInfo(process windows.Handle, offset *WeChatOffset) (*WeChatInfo, error) {
	hMod, err := GetModuleByName(process, "WeChatWin.dll")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	baseAddress := uintptr(hMod)

	nickname, err := ReadStringFromMemory(process, baseAddress+uintptr(offset.Nickname), 64)
	if err != nil {
		return nil, errors.Wrapf(err, "read nickname failed")
	}

	account, err := ReadStringFromMemory(process, baseAddress+uintptr(offset.Account), 32)
	if err != nil {
		return nil, errors.Wrapf(err, "read account failed")
	}

	phone, err := ReadStringFromMemory(process, baseAddress+uintptr(offset.Phone), 64)
	if err != nil {
		return nil, errors.Wrapf(err, "read phone failed")
	}

	key, err := ReadKeyFromMemory(process, baseAddress+uintptr(offset.Key))
	if err != nil {
		return nil, errors.Wrapf(err, "read key failed")
	}

	wxID, err := ReadWXIDFromMemory(process)
	if err != nil {
		return nil, errors.Wrapf(err, "read wxID failed")
	}

	wxDir, err := GetWXDirFromReg()
	if err != nil {
		return nil, errors.Wrapf(err, "get wxDir failed")
	}
	wxIDDir := filepath.Join(wxDir, wxID)

	return &WeChatInfo{
		Nickname: nickname,
		Account:  account,
		Phone:    phone,
		Key:      key,
		WXID:     wxID,
		WXDir:    wxIDDir,
	}, nil
}

func ReadKeyFromMemory(process windows.Handle, address uintptr) (string, error) {
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
		return "", errors.New("read key failed")
	}

	return fmt.Sprintf("%x", buf), nil
}

func ReadWXIDFromMemory(process windows.Handle) (string, error) {
	addrs, err := ScanMemory(process, "\\Msg\\FTSContact")
	if err != nil {
		return "", err
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
