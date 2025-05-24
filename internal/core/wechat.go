package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const KeySize = 32

func DecryptDB(keyStr string, input io.Reader, output io.Writer) error {
	const blockSize = 4096

	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return errors.WithStack(err)
	}

	data, err := io.ReadAll(input)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(data) < blockSize {
		return errors.New("invalid db file")
	}

	firstBlock := data[:blockSize]

	salt := firstBlock[:16]
	macSalt := make([]byte, 16)
	for i := range salt {
		macSalt[i] = salt[i] ^ 58
	}

	byteHmac := pbkdf2.Key(key, salt, 64000, KeySize, sha1.New)
	macKey := pbkdf2.Key(byteHmac, macSalt, 2, KeySize, sha1.New)

	expectedMAC := firstBlock[len(firstBlock)-32 : len(firstBlock)-12]

	hash := hmac.New(sha1.New, macKey)
	hash.Write(firstBlock[16:4064])
	hash.Write([]byte{0x01, 0x00, 0x00, 0x00})

	if !hmac.Equal(hash.Sum(nil), expectedMAC) {
		return errors.New("wrong key")
	}

	if _, err := output.Write([]byte("SQLite format 3\x00")); err != nil {
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

		if _, err := output.Write(plaintext); err != nil {
			return errors.WithStack(err)
		}
		if _, err := output.Write(tail); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}
