/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/charmbracelet/log"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/saltfishpr/wxdump/internal/core/v2"
)

// findCmd represents the find command
var findCmd = &cobra.Command{
	Use:   "find",
	Short: "在微信进程中查找数据",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		value := args[0]
		valueType, err := cmd.Flags().GetString("type")
		if err != nil {
			return errors.WithStack(err)
		}

		var target any
		switch valueType {
		case "string":
			target = value
		default:
			return errors.Errorf("unsupported type: %s", valueType)
		}

		processList, err := core.GetProcessList()
		if err != nil {
			return err
		}
		wechatProcessList := lo.Filter(processList, func(item *core.ProcessEntry, _ int) bool {
			return item.ExeFile == "WeChat.exe"
		})
		for _, wechatProcess := range wechatProcessList {
			if err := processFind(wechatProcess.ProcessID, target); err != nil {
				return err
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(findCmd)

	findCmd.Flags().StringP("type", "t", "string", "搜索值类型")
}

func processFind(processID uint32, target any) error {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	offsets, err := core.ScanMemoryWithOptions(handle, target, core.ScanMemoryOptions{
		ModuleName: "WeChatWin.dll",
		Limit:      100,
	})
	if err != nil {
		return err
	}
	for _, offset := range offsets {
		log.Infof("0x%X", offset)
	}
	return nil
}
