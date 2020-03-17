package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// evenCmd represents the even command
var mitmCmd = &cobra.Command{
	Use:   "mitm",
	Short: "Encrypt file/directories",
	Long:  `Remember your password, if not you won't be able to decrypt your files`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Hello badAss, please provide more args")
	},
}

func init() {
	rootCmd.AddCommand(mitmCmd)
}
