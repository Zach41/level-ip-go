package level_ip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	TCP_FIN uint8 = 0x01
	TCP_SYN uint8 = 0x02
	TCP_RST uint8 = 0x04
	TCP_PSH uint8 = 0x08
	TCP_ACK uint8 = 0x10
	TCP_URG uint8 = 0x20
	TCP_ECN uint8 = 0x40
	TCP_WIN uint8 = 0x80
)

type TCPHdr struct {
	sport   uint16
	dport   uint16
	seq     uint32
	ack     uint32
	hl      uint8 // 4 bits
	rsvd    uint8 // 4 bits
	flags   uint8
	winsz   uint16
	tcpcsum uint16
	urp     uint16
	payload []byte
}

// pseudo-header used for TCP check sum
type TCPIPHdr struct {
	saddr uint32
	daddr uint32
	zero  uint8
	proto uint8
	tlen  uint16
}

func (tcp_hdr *TCPHdr) encode() []byte {
	b := make([]byte, 0)
	b = append(b, writeUint16ToNet(tcp_hdr.sport)...)
	b = append(b, writeUint16ToNet(tcp_hdr.dport)...)
	b = append(b, writeUint32ToNet(tcp_hdr.seq)...)
	b = append(b, writeUint32ToNet(tcp_hdr.ack)...)
	b = append(b, (tcp_hdr.hl<<4)|(tcp_hdr.rsvd&0x0f))
	b = append(b, tcp_hdr.flags)
	b = append(b, writeUint16ToNet(tcp_hdr.winsz)...)
	b = append(b, writeUint16ToNet(tcp_hdr.tcpcsum)...)
	b = append(b, writeUint16ToNet(tcp_hdr.urp)...)
	b = append(b, tcp_hdr.payload...)

	return b
}

func (tcp_hdr *TCPHdr) decode(b []byte) {
	tcp_hdr.sport = readUint16FromNet(b[0:2])
	tcp_hdr.dport = readUint16FromNet(b[2:4])
	tcp_hdr.seq = readUint32FromNet(b[4:8])
	tcp_hdr.ack = readUint32FromNet(b[8:12])
	tcp_hdr.hl = b[12] >> 4
	tcp_hdr.rsvd = b[12] & 0x0f
	tcp_hdr.flags = b[13]
	tcp_hdr.winsz = readUint16FromNet(b[14:16])
	tcp_hdr.tcpcsum = readUint16FromNet(b[16:18])
	tcp_hdr.urp = readUint16FromNet(b[18:20])
	tcp_hdr.payload = b[20:]
}

func initTCPHdr(b []byte) *TCPHdr {
	hdr := new(TCPHdr)
	hdr.decode(b)

	return hdr
}

func (tcp_hdr *TCPHdr) tchecksum(ip_hdr *IPHdr) uint16 {
	tcpip_hdr := new(TCPIPHdr)
	tcpip_hdr.saddr = ip_hdr.saddr
	tcpip_hdr.daddr = ip_hdr.daddr
	tcpip_hdr.zero = 0
	tcpip_hdr.proto = ip_hdr.proto
	tcpip_hdr.tlen = ip_hdr.len - uint16(ip_hdr.ihl*4)

	b := tcpip_hdr.encode()
	b = append(b, tcp_hdr.encode()...)

	return checksum(b, len(b))
}

func (tcpip_hdr *TCPIPHdr) encode() []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, *tcpip_hdr)
	if err != nil {
		fmt.Printf("Serialized TCPIPHdr ERR: %v\n", err)
		os.Exit(1)
	}
	return buf.Bytes()
}

func (tcpip_hdr *TCPIPHdr) decode(b []byte) {
	buf := bytes.NewBuffer(b)
	err := binary.Read(buf, binary.BigEndian, tcpip_hdr)
	if err != nil {
		fmt.Printf("Deserialized TCPIPHdr ERR: %v\n", err)
		os.Exit(1)
	}
}

func tcp_incoming(netdev *NetDev, eth_hdr *EthHdr, ip_hdr *IPHdr, ifce *TunInterface) {
	tcp_hdr := initTCPHdr(ip_hdr.payload)
	DPrintf("Received A TCP Frame:\n%s\n", hexdump(tcp_hdr.encode()))

	if tcp_hdr.tchecksum(ip_hdr) != 0 {
		fmt.Printf("TCP segment checksum failed.\n")
		return
	}
	tcp_outgoing(netdev, eth_hdr, ip_hdr, tcp_hdr, ifce)
}

func tcp_outgoing(netdev *NetDev, eth_hdr *EthHdr, ip_hdr *IPHdr, tcp_hdr *TCPHdr, ifce *TunInterface) {
	// swap src port and dst port
	tcp_hdr.sport, tcp_hdr.dport = tcp_hdr.dport, tcp_hdr.sport

	// if this is a syn datagram
	if (tcp_hdr.flags & TCP_SYN) != 0 {
		DPrintf("Received A TCP SYN.\n")
		tcp_hdr.flags |= TCP_ACK
		tcp_hdr.ack = tcp_hdr.seq + 1
		// FIXME: generate a better seq number
		tcp_hdr.seq = 1024
	}
	// tcp_hdr.hl = 5
	// ip_hdr.len -= 20

	tcp_hdr.tcpcsum = 0

	pseudoip_hdr := new(IPHdr)
	pseudoip_hdr.saddr = ip_hdr.daddr
	pseudoip_hdr.daddr = ip_hdr.saddr
	pseudoip_hdr.proto = ip_hdr.proto
	pseudoip_hdr.ihl = ip_hdr.ihl
	pseudoip_hdr.len = ip_hdr.len

	tcp_hdr.tcpcsum = tcp_hdr.tchecksum(pseudoip_hdr)

	DPrintf("Replying A TCP Request:\n%s\n", hexdump(tcp_hdr.encode()))
	ip_hdr.payload = tcp_hdr.encode()
	ipv4_outgoing(netdev, eth_hdr, ip_hdr, ifce)
}
