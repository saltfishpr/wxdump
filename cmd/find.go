/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/charmbracelet/log"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/spf13/cobra"

	"github.com/saltfishpr/wxdump/internal/core"
)

// findCmd represents the find command
var findCmd = &cobra.Command{
	Use:  "find",
	Args: cobra.ExactArgs(1),
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
			offsets, err := core.FindInMemory(wechatProcess.ProcessID, target, 100)
			if err != nil {
				return err
			}
			log.Info(offsets)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(findCmd)

	findCmd.Flags().StringP("type", "t", "string", "搜索值类型")
}
