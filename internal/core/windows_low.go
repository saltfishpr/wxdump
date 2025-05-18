package core

import (
	"golang.org/x/sys/windows"
)

var (
	modpsapi = windows.NewLazySystemDLL("psapi.dll")

	getMappedFileNameW = modpsapi.NewProc("GetMappedFileNameW")
)
