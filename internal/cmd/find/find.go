package find

import (
	"context"

	"github.com/samber/lo"

	"github.com/saltfishpr/wxdump/internal/core"
)

type Args struct {
	Value any
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
		if err := run(wechatProcess.ProcessID, args.Value); err != nil {
			return err
		}
	}
	return nil
}
