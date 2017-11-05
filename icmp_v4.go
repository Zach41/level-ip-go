package level_ip

import (
	"fmt"
)

const (
	ICMPV4 uint8 = 0x01

	ICMPV4_REPLY           uint8 = 0x00
	ICMPV4_DST_UNREACHABLE uint8 = 0x03
	ICMPV4_SRC_QUENCH      uint8 = 0x04
	ICMPV4_REDIRECT        uint8 = 0x05
	ICMPV4_ECHO            uint8 = 0x08
	ICMPV4_ROUTER_ADV      uint8 = 0x09
	ICMPV4_ROUTER_SOL      uint8 = 0x0a
	ICMPV4_TIMEOUT         uint8 = 0x0b
	ICMPV4_MALFORMED       uint8 = 0x0c
)

type ICMPV4Hdr struct {
	ty      uint8
	code    uint8
	csum    uint16
	payload []byte
}

type ICMPV4_EchoHdr struct {
	id      uint16
	seq     uint16
	payload []byte
}

type ICMPV4_DstUnreachableHdr struct {
	unused   uint8
	len      uint8
	variable uint16
	payload  []byte
}

func (icmp_hdr *ICMPV4Hdr) encode() []byte {
	b := make([]byte, 0)
	b = append(b, icmp_hdr.ty)
	b = append(b, icmp_hdr.code)
	b = append(b, writeUint16ToNet(icmp_hdr.csum)...)
	b = append(b, icmp_hdr.payload...)

	return b
}

func (icmp_hdr *ICMPV4Hdr) decode(b []byte) {
	icmp_hdr.ty = b[0]
	icmp_hdr.code = b[1]
	icmp_hdr.csum = readUint16FromNet(b[2:4])
	icmp_hdr.payload = b[4:]
}

func (icmp_v4_echo *ICMPV4_EchoHdr) encode() []byte {
	b := make([]byte, 0)
	b = append(b, writeUint16ToNet(icmp_v4_echo.id)...)
	b = append(b, writeUint16ToNet(icmp_v4_echo.seq)...)
	b = append(b, icmp_v4_echo.payload...)

	return b
}

func (icmp_v4_echo *ICMPV4_EchoHdr) decode(b []byte) {
	icmp_v4_echo.id = readUint16FromNet(b[0:2])
	icmp_v4_echo.seq = readUint16FromNet(b[2:4])
	icmp_v4_echo.payload = b[4:]
}

func (icmp_v4_dst *ICMPV4_DstUnreachableHdr) encode() []byte {
	b := make([]byte, 0)
	b = append(b, icmp_v4_dst.unused)
	b = append(b, icmp_v4_dst.len)
	b = append(b, writeUint16ToNet(icmp_v4_dst.variable)...)
	b = append(b, icmp_v4_dst.payload...)

	return b
}

func (icmp_v4_dst *ICMPV4_DstUnreachableHdr) decode(b []byte) {
	icmp_v4_dst.unused = b[0]
	icmp_v4_dst.len = b[1]
	icmp_v4_dst.variable = readUint16FromNet(b[2:4])
	icmp_v4_dst.payload = b[4:]
}

func initICMPV4(ip_hdr *IPHdr) *ICMPV4Hdr {
	hdr := &ICMPV4Hdr{}
	hdr.decode(ip_hdr.payload)

	return hdr
}

func icmp_incoming(netdev *NetDev, eth_hdr *EthHdr, ip_hdr *IPHdr, ifce *TunInterface) {
	icmpv4_hdr := initICMPV4(ip_hdr)

	switch icmpv4_hdr.ty {
	case ICMPV4_ECHO:
		icmp_reply(netdev, eth_hdr, ip_hdr, ifce)
	default:
		DPrintf("Received A ICMPv4 Datagram. Type: %d\n", icmpv4_hdr.ty)
	}
}

func icmp_reply(netdev *NetDev, eth_hdr *EthHdr, ip_hdr *IPHdr, ifce *TunInterface) {
	icmp_len := int(ip_hdr.len) - int(ip_hdr.ihl*4)

	csum := checksum(ip_hdr.payload, icmp_len)
	if csum != 0 {
		fmt.Println("ICMP Chechsum error.")
		return
	}

	icmp_hdr := initICMPV4(ip_hdr)
	icmp_hdr.csum = 0
	icmp_hdr.ty = ICMPV4_REPLY
	icmp_hdr.csum = checksum(icmp_hdr.encode(), icmp_len)

	ip_hdr.payload = icmp_hdr.encode()

	ipv4_outgoing(netdev, eth_hdr, ip_hdr, ifce)
}
