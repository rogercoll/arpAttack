package utils

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// readARP loops until 'stop' is closed. Handles incoming ARP responses
func ReadARP(handler *pcap.Handle, iface *net.Interface, addresses chan []byte, stop chan struct{}) {
	src := gopacket.NewPacketSource(handler, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			addresses <- arp.SourceHwAddress
		}
	}
}

func WriteARP(handler *pcap.Handle, iface *net.Interface, addr *net.IPNet, dstMAC, dstAddr []byte) error {
	//we want to request the mac address => broadcast address
	eth := layers.Ethernet{
		SrcMAC: iface.HardwareAddr,
		//Broadcast 		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstAddr,
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err := handler.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func FormatAddr(addr string) []byte {
	ip := net.ParseIP(addr)
	ip = ip.To4()
	fmt.Printf("%+v\n", ip)
	return ip
}
