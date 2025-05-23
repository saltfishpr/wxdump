package cmd

import (
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

var version string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "wxdump.exe",
	Version: version,

	SilenceErrors: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		log.Fatalf("Error: %+v", err)
	}
}
