/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/saltfishpr/wxdump/internal/cmd/decrypt"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "解密微信客户端数据库",
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDir, err := cmd.Flags().GetString("output_dir")
		if err != nil {
			return errors.WithStack(err)
		}
		return decrypt.Run(cmd.Context(), decrypt.Args{
			OutputDir: outputDir,
		})
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringP("output_dir", "o", "output", "解密后的数据库文件输出路径")
}
