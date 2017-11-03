package level_ip

import (
	"fmt"
	"net"
	"os"
)

type arpstate uint32

const (
	ARP_FREE     arpstate = 0 // never used
	ARP_WAITING  arpstate = 1
	ARP_RESOLVED arpstate = 2

	ARP_REQUEST uint16 = 0x0001
	ARP_REPLY   uint16 = 0x0002

	ARP_ETHERNET uint16 = 0x0001
	ARP_IPV4     uint16 = 0x0800
)

type ArpHdr struct {
	hwtype  uint16
	protype uint16
	hwsize  byte
	prosize byte
	opcode  uint16
	data    []byte
}

type ArpIpv4 struct {
	smac net.HardwareAddr
	sip  net.IP
	dmac net.HardwareAddr
	dip  net.IP
}

type ArpCacheEntry struct {
	hwtype uint16
	smac   net.HardwareAddr
	sip    net.IP
	state  arpstate
}

var arpCaches = map[string]ArpCacheEntry{}

func updateTranslationTable(arp_hdr *ArpHdr, data *ArpIpv4) bool {
	key := data.sip.String()
	entry, ok := arpCaches[key]
	if !ok || entry.hwtype != arp_hdr.hwtype {
		return false
	}

	copy(entry.smac[:], data.smac[:])
	arpCaches[key] = entry
	return true
}

func insertTranslateTable(arp_hdr *ArpHdr, data *ArpIpv4) bool {
	key := data.sip.String()
	_, ok := arpCaches[key]
	if ok {
		return false
	}
	entry := ArpCacheEntry{hwtype: arp_hdr.hwtype, state: ARP_RESOLVED}
	copy(entry.sip[:], data.sip)
	copy(entry.smac[:], data.smac)

	arpCaches[key] = entry
	return true
}

func initArpHdr(header []byte) ArpHdr {
	hdr := ArpHdr{}
	hdr.hwtype = readUint16FromNet(header[0:2])
	hdr.protype = readUint16FromNet(header[2:4])
	hdr.hwsize = 6
	hdr.prosize = 4
	hdr.opcode = readUint16FromNet(header[6:8])
	hdr.data = header[8:]

	return hdr
}

func initArpData(data []byte) ArpIpv4 {
	arpdata := ArpIpv4{
		smac: data[0:6],
		sip:  data[6:10],
		dmac: data[10:16],
		dip:  data[16:20],
	}
	return arpdata
}

func arpIncoming(dev *NetDev, eth_hdr *EthHdr, ifce *TunInterface) {
	arp_hdr := initArpHdr(eth_hdr.payload)

	if arp_hdr.hwtype != ARP_ETHERNET {
		fmt.Println("Unsupported hardware type.")
		os.Exit(1)
	}
	if arp_hdr.protype != ARP_IPV4 {
		fmt.Printf("Unsupported protocol: %04x\n", arp_hdr.protype)
		os.Exit(1)
	}

	arpdata := initArpData(arp_hdr.data)

	merge := updateTranslationTable(&arp_hdr, &arpdata)
	if !merge && !insertTranslateTable(&arp_hdr, &arpdata) {
		fmt.Println("ERR: updating translation table failed.")
		os.Exit(1)
	}

	switch arp_hdr.opcode {
	case ARP_REQUEST:
		arp_reply(dev, eth_hdr, &arp_hdr, ifce)
	case ARP_REPLY:
		DPrintf("Received A ARP Reply\n")
	default:
		DPrintf("Unsupported operation\n")
	}
}

func arp_reply(dev *NetDev, eth_hdr *EthHdr, arp_hdr *ArpHdr, ifce *TunInterface) {
	arpdata := initArpData(arp_hdr.data)

	copy(arpdata.dmac[:], arpdata.smac[:])
	copy(arpdata.dip[:], arpdata.sip[:])
	copy(arpdata.smac[:], dev.hwAddr[:])
	copy(arpdata.sip[:], dev.addr[:])

	arp_hdr.opcode = ARP_REPLY

	copy(eth_hdr.dmac[:], eth_hdr.smac[:])
	copy(eth_hdr.smac[:], dev.hwAddr[:])

	frame := serializeFrameARP(eth_hdr, arp_hdr, &arpdata)

	_, err := ifce.Write(frame)
	if err != nil {
		fmt.Println("Writing data error: ", err)
		os.Exit(1)
	}
}
