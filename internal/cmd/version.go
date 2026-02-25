package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the rosa-boundary version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("rosa-boundary %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
