package level_ip

import (
	"fmt"
)

const (
	IPV4 uint8 = 0x04
)

type IPHdr struct {
	version    uint8
	ihl        uint8
	tos        uint8
	len        uint16
	id         uint16
	flags      uint16
	frag_offet uint16
	ttl        uint8
	proto      uint8
	csum       uint16
	saddr      uint32
	daddr      uint32
	payload    []byte
}

func (ip_hdr *IPHdr) encode() []byte {
	b := make([]byte, 0)
	b = append(b, (ip_hdr.version<<4)|(ip_hdr.ihl&0x0f))
	b = append(b, ip_hdr.tos)
	b = append(b, writeUint16ToNet(ip_hdr.len)...)
	b = append(b, writeUint16ToNet(ip_hdr.id)...)
	flags_fragoff := (ip_hdr.flags << 13) | (ip_hdr.frag_offet & 0x1fff)
	b = append(b, writeUint16ToNet(flags_fragoff)...)
	b = append(b, ip_hdr.ttl)
	b = append(b, ip_hdr.proto)
	b = append(b, writeUint16ToNet(ip_hdr.csum)...)
	b = append(b, writeUint32ToNet(ip_hdr.saddr)...)
	b = append(b, writeUint32ToNet(ip_hdr.daddr)...)
	b = append(b, ip_hdr.payload...)

	return b
}

func (ip_hdr *IPHdr) decode(b []byte) {
	ip_hdr.version = b[0] >> 4
	ip_hdr.ihl = b[0] & 0xff
	ip_hdr.tos = b[1]
	ip_hdr.len = readUint16FromNet(b[2:4])
	ip_hdr.id = readUint16FromNet(b[4:6])
	flags_fragoff := readUint16FromNet(b[6:8])
	ip_hdr.flags = flags_fragoff >> 13
	ip_hdr.frag_offet = flags_fragoff & 0x1fff
	ip_hdr.ttl = b[8]
	ip_hdr.proto = b[9]
	ip_hdr.csum = readUint16FromNet(b[10:12])
	ip_hdr.saddr = readUint32FromNet(b[12:16])
	ip_hdr.daddr = readUint32FromNet(b[16:20])
	ip_hdr.payload = b[20:]
}

func initIPV4Hdr(eth_hdr *EthHdr) *IPHdr {
	hdr := &IPHdr{}
	hdr.decode(eth_hdr.payload)

	return hdr
}

func ipv4_incoming(netdev *NetDev, eth_hdr *EthHdr, ifce *TunInterface) {
	DPrintf("Received A IP Datagram.\n%s\n", hexdump(eth_hdr.payload))
	ip_hdr := initIPV4Hdr(eth_hdr)

	if ip_hdr.version != IPV4 {
		fmt.Printf("Datagram version was not IPV4\n")
		return
	}

	if ip_hdr.ihl < 5 {
		fmt.Printf("IPV4 Header is at least 5 length long, but got %d\n", ip_hdr.ihl)
		return
	}

	if ip_hdr.ttl == 0 {
		fmt.Printf("Time to live of Datagram reached 0.\n")
		return
	}

	csum := checksum(ip_hdr.encode(), int(ip_hdr.ihl*4))

	if csum != 0 {
		// data not valid
		return
	}

	switch ip_hdr.proto {
	case ICMPV4:
		icmp_incoming(netdev, eth_hdr, ip_hdr, ifce)
	default:
		DPrintf("IP Datagram's protocol: %d\n", ip_hdr.proto)
	}
}

func ipv4_outgoing(netdev *NetDev, eth_hdr *EthHdr, ip_hdr *IPHdr, ifce *TunInterface) {

	tmpaddr := ip_hdr.saddr
	ip_hdr.saddr = ip_hdr.daddr
	ip_hdr.daddr = tmpaddr

	ip_hdr.csum = 0
	ip_hdr.csum = checksum(ip_hdr.encode(), int(ip_hdr.ihl*4))

	netdev.transimit(eth_hdr, eth_hdr.ethertype, eth_hdr.smac, ip_hdr, ifce)
}
