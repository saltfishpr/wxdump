/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/saltfishpr/wxdump/internal/cmd/find"
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

		return find.Run(cmd.Context(), find.Args{
			Value: target,
		})
	},
}

func init() {
	rootCmd.AddCommand(findCmd)

	findCmd.Flags().StringP("type", "t", "string", "搜索值类型")
}
