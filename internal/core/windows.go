package core

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

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
