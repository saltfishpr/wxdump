/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/saltfishpr/wxdump/internal/cmd/decrypt"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "解密微信客户端数据库",
	RunE: func(cmd *cobra.Command, args []string) error {
		return decrypt.Run(cmd.Context(), decrypt.Args{
			OutputDir: cmd.Flag("output_dir").Value.String(),
			Account:   cmd.Flag("account").Value.String(),
		})
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringP("output_dir", "o", "output", "解密后的数据库文件输出路径")
	decryptCmd.Flags().StringP("account", "a", "", "指定微信号，缩小key搜索范围")
}
