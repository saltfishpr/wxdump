package main

import (
	"fmt"

	"github.com/charmbracelet/log"

	"github.com/saltfishpr/wxdump/cmd"
)

func init() {
	log.SetReportCaller(true)
	log.SetCallerFormatter(func(file string, line int, fn string) string {
		return fmt.Sprintf(" %s:%d ", file, line)
	})
}

func main() {
	cmd.Execute()
}
