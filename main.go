package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/log"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/spf13/cobra"

	"github.com/saltfishpr/wxdump/internal/core"
)

var version string

func init() {
	log.SetReportCaller(true)
	log.SetCallerFormatter(func(file string, line int, fn string) string {
		return fmt.Sprintf(" %s:%d ", file, line)
	})
}

func main() {
	rootCmd := &cobra.Command{
		Use:     "wxdump.exe",
		Version: version,

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
				execPath, err := core.GetProcessExePath(wechatProcess.ProcessID)
				if err != nil {
					return err
				}
				version, err := core.GetFileVersionInfo(execPath)
				if err != nil {
					return err
				}
				bits, err := core.GetPEBits(execPath)
				if err != nil {
					return err
				}
				addressLen := bits / 8

				offset, ok := offsets[version]
				if !ok {
					return errors.Errorf("version %s not support", version)
				}

				weChatInfo, err := core.GetWeChatInfo(wechatProcess.ProcessID, addressLen, offset)
				if err != nil {
					return err
				}
				userOutputDir := filepath.Join(outputDir, weChatInfo.WXID)
				if err := ensureDir(userOutputDir); err != nil {
					return err
				}
				for _, dbFilename := range weChatInfo.DBFilenames {
					if err := core.DecryptDB(weChatInfo.Key, dbFilename, filepath.Join(userOutputDir, filepath.Base(dbFilename))); err != nil {
						log.Warn("decrypt db failed", "filename", dbFilename, "error", err)
					}
				}
			}
			return nil
		},
	}

	rootCmd.Flags().StringP("output_dir", "o", "output", "解密数据库文件输出路径")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %+v\n", err)
	}
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
