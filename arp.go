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

func (arp_hdr *ArpHdr) encode() []byte {
	b := make([]byte, 0)
	b = append(b, writeUint16ToNet(arp_hdr.hwtype)...)
	b = append(b, writeUint16ToNet(arp_hdr.protype)...)
	b = append(b, arp_hdr.hwsize)
	b = append(b, arp_hdr.prosize)
	b = append(b, writeUint16ToNet(arp_hdr.opcode)...)
	b = append(b, arp_hdr.data...)

	return b
}

func (arp_hdr *ArpHdr) decode(b []byte) {
	arp_hdr.hwtype = readUint16FromNet(b[0:2])
	arp_hdr.protype = readUint16FromNet(b[2:4])
	arp_hdr.hwsize = b[4]
	arp_hdr.prosize = b[5]
	arp_hdr.opcode = readUint16FromNet(b[6:8])
	arp_hdr.data = b[8:]
}

func (arp_ipv4 *ArpIpv4) encode() []byte {
	b := make([]byte, 0)
	b = append(b, arp_ipv4.smac...)
	b = append(b, arp_ipv4.sip...)
	b = append(b, arp_ipv4.dmac...)
	b = append(b, arp_ipv4.dip...)

	return b
}

func (arp_ipv4 *ArpIpv4) decode(b []byte) {
	arp_ipv4.smac = b[0:6]
	arp_ipv4.sip = b[6:10]
	arp_ipv4.dmac = b[10:16]
	arp_ipv4.dip = b[16:20]
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

func initArpHdr(header []byte) *ArpHdr {
	hdr := &ArpHdr{}
	hdr.decode(header)

	return hdr
}

func initArpData(data []byte) *ArpIpv4 {
	arpdata := &ArpIpv4{}
	arpdata.decode(data)
	return arpdata
}

func arpIncoming(dev *NetDev, eth_hdr *EthHdr, ifce *TunInterface) {
	DPrintf("ARP Request Incoming.\nETH_FRAME:\n%s\n", hexdump(eth_hdr.encode()))

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

	merge := updateTranslationTable(arp_hdr, arpdata)
	if !merge && !insertTranslateTable(arp_hdr, arpdata) {
		fmt.Println("ERR: updating translation table failed.")
		os.Exit(1)
	}

	switch arp_hdr.opcode {
	case ARP_REQUEST:
		arp_reply(dev, eth_hdr, arp_hdr, ifce)
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

	DPrintf("Reply A ARP Request\n\tSRC: %s\n\tDST: %s\n", hexdump(arpdata.smac), hexdump(arpdata.dmac))

	arp_hdr.opcode = ARP_REPLY

	dev.transimit(eth_hdr, eth_hdr.ethertype, eth_hdr.smac, arp_hdr, ifce)
}
