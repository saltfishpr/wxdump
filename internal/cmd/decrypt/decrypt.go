package decrypt

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/charmbracelet/log"
	"github.com/pkg/errors"
	"github.com/samber/lo"

	"github.com/saltfishpr/wxdump/internal/core"
)

type Args struct {
	OutputDir string
}

func Run(ctx context.Context, args Args) error {
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
		version, err := core.GetWeChatVersion(wechatProcess.ProcessID)
		if err != nil {
			return err
		}
		offset, ok := offsets[version]
		if !ok {
			return errors.Errorf("version %s not support", version)
		}

		if err := run(wechatProcess.ProcessID, args.OutputDir, offset); err != nil {
			log.Warn("decrypt failed", "process_id", wechatProcess.ProcessID, "error", err)
		}
	}
	return nil
}

func run(processID uint32, outputDir string, offset *core.WeChatOffset) error {
	weChatInfo, err := core.GetWeChatInfo(processID, offset)
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
