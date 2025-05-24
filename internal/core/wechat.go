package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
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
