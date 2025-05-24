/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/charmbracelet/log"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/saltfishpr/wxdump/internal/core"
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

		processList, err := core.GetProcessList()
		if err != nil {
			return err
		}
		wechatProcessList := lo.Filter(processList, func(item *core.ProcessEntry, _ int) bool {
			return item.ExeFile == "WeChat.exe"
		})

		offsets, err := core.LoadWeChatOffsets()
		if err != nil {
			return err
		}

		for _, wechatProcess := range wechatProcessList {
			if err := processDecrypt(wechatProcess.ProcessID, offsets, outputDir); err != nil {
				return err
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringP("output_dir", "o", "output", "解密后的数据库文件输出路径")
}

func processDecrypt(processID uint32, offsets map[string]*core.WeChatOffset, outputDir string) error {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return errors.WithStack(err)
	}
	defer windows.CloseHandle(handle) //nolint

	execPath, err := core.GetModuleFileNameEx(handle, 0)
	if err != nil {
		return err
	}
	version, err := core.GetFileVersionInfo(execPath)
	if err != nil {
		return err
	}

	offset, ok := offsets[version]
	if !ok {
		return errors.Errorf("version %s not support", version)
	}

	weChatInfo, err := core.GetWeChatInfo(handle, offset)
	if err != nil {
		return err
	}
	log.Infof("decrypt for user: %s", weChatInfo.WXID)

	userOutputDir := filepath.Join(outputDir, weChatInfo.WXID)
	if err := ensureDir(userOutputDir); err != nil {
		return err
	}

	return filepath.WalkDir(weChatInfo.WXDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".db" {
			return nil
		}
		if filepath.Base(path) == "xInfo.db" {
			return nil // xInfo.db 不需要解密
		}
		if err := core.DecryptDB(weChatInfo.Key, path, filepath.Join(userOutputDir, filepath.Base(path))); err != nil {
			log.Warn("decrypt db failed", "filename", path, "error", err)
		}
		return nil
	})
}

func ensureDir(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return errors.WithStack(err)
		}
	} else if err != nil {
		return errors.WithStack(err)
	} else if !info.IsDir() {
		// 路径存在但不是目录
		return errors.New("path exists but is not a directory")
	}
	return nil
}
