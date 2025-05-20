package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const KeySize = 32

//go:embed WX_OFFS.json
var WX_OFFS []byte

type WeChatOffset struct {
	Nickname int `json:"nickname"`
	Account  int `json:"account"`
	Phone    int `json:"phone"`
	Key      int `json:"key"`
}

func LoadWeChatOffsets() (map[string]*WeChatOffset, error) {
	const (
		idxNickname = iota
		idxAccount
		idxPhone
		idxEmail
		idxKey
	)

	data := make(map[string][]int)
	if err := json.Unmarshal(WX_OFFS, &data); err != nil {
		return nil, errors.WithStack(err)
	}

	res := make(map[string]*WeChatOffset)
	for k, v := range data {
		res[k] = &WeChatOffset{
			Nickname: v[idxNickname],
			Account:  v[idxAccount],
			Phone:    v[idxPhone],
			Key:      v[idxKey],
		}
	}
	return res, nil
}

type WeChatInfo struct {
	Nickname string
	Account  string
	Phone    string
	Key      string
	WXID     string
	WXDir    string

	DBFilenames []string
}

func GetWeChatInfo(processID uint32, addressLen int, offset *WeChatOffset) (*WeChatInfo, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	memInfoList, err := GetMemoryInformation(handle)
	if err != nil {
		log.Fatalf("%+v\n", err)
	}
	memInfo, ok := lo.Find(memInfoList, func(memInfo *MemoryInformation) bool {
		return strings.Contains(memInfo.Filename, "WeChatWin.dll")
	})
	if !ok {
		return nil, errors.New("WeChatWin.dll not found")
	}

	nickname, err := ReadStringFromMemory(handle, memInfo.BaseAddress+uintptr(offset.Nickname), 64)
	if err != nil {
		return nil, errors.Wrapf(err, "read nickname failed")
	}

	account, err := ReadStringFromMemory(handle, memInfo.BaseAddress+uintptr(offset.Account), 32)
	if err != nil {
		return nil, errors.Wrapf(err, "read account failed")
	}

	phone, err := ReadStringFromMemory(handle, memInfo.BaseAddress+uintptr(offset.Phone), 64)
	if err != nil {
		return nil, errors.Wrapf(err, "read phone failed")
	}

	key, err := ReadKeyFromMemory(handle, memInfo.BaseAddress+uintptr(offset.Key), addressLen)
	if err != nil {
		return nil, errors.Wrapf(err, "read key failed")
	}

	wxID, err := ReadWXIDFromMemory(handle)
	if err != nil {
		return nil, errors.Wrapf(err, "read wxID failed")
	}

	wxDir, err := GetWXDirFromReg()
	if err != nil {
		return nil, errors.Wrapf(err, "get wxDir failed")
	}
	wxIDDir := filepath.Join(wxDir, wxID)

	var dbFilenames []string
	if err := filepath.WalkDir(wxIDDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // 可根据需要自定义错误处理
		}
		if !d.IsDir() && filepath.Ext(path) == ".db" {
			dbFilenames = append(dbFilenames, path)
		}
		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "get db list failed")
	}

	return &WeChatInfo{
		Nickname: nickname,
		Account:  account,
		Phone:    phone,
		Key:      key,
		WXID:     wxID,
		WXDir:    wxIDDir,

		DBFilenames: dbFilenames,
	}, nil
}

func ReadKeyFromMemory(process windows.Handle, address uintptr, addressLen int) (string, error) {
	array := make([]byte, addressLen)
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(process, address, &array[0], uintptr(addressLen), &bytesRead); err != nil {
		return "", errors.WithStack(err)
	}

	var keyAddress uint64
	switch addressLen {
	case 4:
		keyAddress = uint64(binary.LittleEndian.Uint32(array))
	case 8:
		keyAddress = binary.LittleEndian.Uint64(array)
	default:
		return "", errors.Errorf("unsupported address length: %d", addressLen)
	}

	keyBuf := make([]byte, KeySize)
	if err := windows.ReadProcessMemory(process, uintptr(keyAddress), &keyBuf[0], KeySize, &bytesRead); err != nil {
		return "", errors.WithStack(err)
	}

	return fmt.Sprintf("%x", keyBuf), nil
}

func FindInMemory(processID uint32, target any, limit int) ([]uintptr, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	memInfoList, err := GetMemoryInformation(handle)
	if err != nil {
		log.Fatalf("%+v\n", err)
	}
	memInfo, ok := lo.Find(memInfoList, func(memInfo *MemoryInformation) bool {
		return strings.Contains(memInfo.Filename, "WeChatWin.dll")
	})
	if !ok {
		return nil, errors.New("WeChatWin.dll not found")
	}

	addrs, err := SearchInMemory(handle, target, limit)
	if err != nil {
		return nil, err
	}

	return lo.Map(addrs, func(item uintptr, _ int) uintptr {
		return item - memInfo.BaseAddress
	}), nil
}

func ReadWXIDFromMemory(handle windows.Handle) (string, error) {
	addrs, err := SearchInMemory(handle, "\\Msg\\FTSContact", 100)
	if err != nil {
		return "", err
	}
	var ids []string
	for _, addr := range addrs {
		s, err := ReadStringFromMemory(handle, addr-30, 80)
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

func DecryptDB(keyStr string, input string, output string) error {
	const blockSize = 4096

	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return errors.WithStack(err)
	}

	data, err := os.ReadFile(input)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(data) < blockSize {
		return errors.New("invalid db file")
	}

	first := data[:blockSize]
	salt := first[:16]
	expectedMAC := first[len(first)-32 : len(first)-12]

	macSalt := make([]byte, 16)
	for i := range salt {
		macSalt[i] = salt[i] ^ 58
	}

	byteHmac := pbkdf2.Key(key, salt, 64000, KeySize, sha1.New)
	macKey := pbkdf2.Key(byteHmac, macSalt, 2, KeySize, sha1.New)

	hash := hmac.New(sha1.New, macKey)
	hash.Write(first[16:4064])
	hash.Write([]byte{0x01, 0x00, 0x00, 0x00})

	if !hmac.Equal(hash.Sum(nil), expectedMAC) {
		return errors.New("wrong key")
	}

	outFile, err := os.Create(output)
	if err != nil {
		return errors.WithStack(err)
	}
	defer outFile.Close()

	if _, err := outFile.Write([]byte("SQLite format 3\x00")); err != nil {
		return errors.WithStack(err)
	}

	for i := 0; i < len(data); i += blockSize {
		var block []byte
		if i == 0 {
			block = data[16:blockSize]
		} else {
			end := i + blockSize
			if end > len(data) {
				end = len(data)
			}
			block = data[i:end]
		}

		if len(block) < 48 {
			return errors.New("Block too small for decryption")
		}

		iv := block[len(block)-48 : len(block)-32]
		ciphertext := block[:len(block)-48]
		tail := block[len(block)-48:]

		blockCipher, err := aes.NewCipher(byteHmac)
		if err != nil {
			return errors.WithStack(err)
		}

		mode := cipher.NewCBCDecrypter(blockCipher, iv)
		plaintext := make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)

		if _, err := outFile.Write(plaintext); err != nil {
			return errors.WithStack(err)
		}
		if _, err := outFile.Write(tail); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}
