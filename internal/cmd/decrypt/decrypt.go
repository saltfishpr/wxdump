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
	Account   string
}

func Run(ctx context.Context, args Args) error {
	processList, err := core.GetProcessList()
	if err != nil {
		return err
	}
	wechatProcessList := lo.Filter(processList, func(item *core.ProcessEntry, _ int) bool {
		return item.ExeFile == "WeChat.exe"
	})

	for _, wechatProcess := range wechatProcessList {
		version, err := core.GetWeChatVersion(wechatProcess.ProcessID)
		if err != nil {
			return err
		}
		log.Infof("wechat version: %s", version)

		// TODO 校验version为 3.x.x.x

		wxID, err := core.ScanWXIDFromMemory(wechatProcess.ProcessID)
		if err != nil {
			return err
		}

		userOutputDir := filepath.Join(args.OutputDir, wxID)
		if err := ensureDir(userOutputDir); err != nil {
			return err
		}

		if err := run(wechatProcess.ProcessID, wxID, userOutputDir, args.Account); err != nil {
			log.Warn("decrypt failed", "process_id", wechatProcess.ProcessID, "error", err)
		}
	}
	return nil
}

func run(processID uint32, wxID string, outputDir string, account string) error {
	log.Infof("decrypt for user: %s", wxID)

	wxDir, err := core.GetWXDirFromReg()
	if err != nil {
		return err
	}
	wxIDDir := filepath.Join(wxDir, wxID)

	keyStr, err := core.CrackDatabaseKey(processID, filepath.Join(wxIDDir, "Msg", "Applet.db"), core.CrackDatabaseKeyOptions{
		Account: account,
	})
	if err != nil {
		return err
	}

	return filepath.WalkDir(wxIDDir, func(path string, d fs.DirEntry, err error) error {
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

		if err := decryptDB(keyStr, path, outputDir); err != nil {
			log.Warn("decrypt db failed", "filename", path, "error", err)
		}
		return nil
	})
}

func decryptDB(keyStr string, filename string, outputDir string) error {
	inputFile, err := os.Open(filename)
	if err != nil {
		return errors.WithStack(err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(filepath.Join(outputDir, filepath.Base(filename)))
	if err != nil {
		return errors.WithStack(err)
	}
	defer outputFile.Close()

	return core.DecryptDB(keyStr, inputFile, outputFile)
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
