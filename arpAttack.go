package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}

func writeARP(handler *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	//we want to request the mac address => broadcast address
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
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
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handler.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// readARP loops until 'stop' is closed. Handles incoming ARP responses
func readARP(handler *pcap.Handle, iface *net.Interface, stop chan struct{}) {
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
			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

func scan(iface *net.Interface) error {
	var faddr *net.IPNet //final address
	if addrs, err := iface.Addrs(); err != nil {
		return err
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
		return errors.New("No good IP found for that interface")
	} else if faddr.IP[0] == 127 {
		return errors.New("Skipping localhost")
	} else if faddr.IP[0] == 172 {
		return errors.New("Skipping docker interfaces")
	} else if faddr.Mask[0] != 0xff || faddr.Mask[1] != 0xff {
		return errors.New("Network(mask) to large for that interface")
	}

	log.Printf("Using network range %v for interface %v", faddr, iface.Name)

	//pcap => packet capturer
	/*
		In networking terms, a computer having its network interface card set to “promiscuous mode”
		receives all packets on the same network segment.
		In “normal mode,” a network card accepts only packets addressed to its MAC Address.
	*/
	handler, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handler.Close()

	stop := make(chan struct{})
	go readARP(handler, iface, stop)
	defer close(stop)

	for {
		if err := writeARP(handler, iface, faddr); err != nil {
			log.Printf("error writing packets on %v: %v", iface.Name, err)
			return err
		}
		//10 seconds should be more than enough to recive a response
		time.Sleep(10 * time.Second)
	}
	return nil
}

func main() {
	var wg sync.WaitGroup
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	for _, iface := range ifaces {
		fmt.Printf("%+v\n", iface)
		wg.Add(1)
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface); err != nil {
				log.Printf("Interface %s error: %v", iface.Name, err)
			}
		}(iface)
	}
	wg.Wait()
}
