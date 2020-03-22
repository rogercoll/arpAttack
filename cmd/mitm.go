package cmd

import (
	"log"

	"github.com/rogercoll/arpAttack/pkg/mitm"
	"github.com/spf13/cobra"
)

// evenCmd represents the even command
var mitmCmd = &cobra.Command{
	Use:   "mitm",
	Short: "Encrypt file/directories",
	Long:  `Remember your password, if not you won't be able to decrypt your files`,
	Run: func(cmd *cobra.Command, args []string) {
		err := mitm.Run("wlp58s0", "192.168.1.69", "192.168.1.1")
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(mitmCmd)
}
