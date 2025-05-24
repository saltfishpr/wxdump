package find

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	"golang.org/x/sys/windows"

	"github.com/saltfishpr/wxdump/internal/core"
)

func run(processID uint32, value any) error {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	addrs, err := core.ScanMemoryWithOptions(handle, value, core.ScanMemoryOptions{
		ModuleName: "WeChatWin.dll",
		Limit:      100,
	})
	if err != nil {
		return err
	}
	hexAddrs := lo.Map(addrs, func(addr uintptr, _ int) string {
		return fmt.Sprintf("0x%x", addr)
	})
	fmt.Println(hexAddrs)
	return nil
}
