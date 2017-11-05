package level_ip

import (
	"net"
)

const (
	ETH_P_ARP uint16 = 0x0806
	ETH_P_IP  uint16 = 0x0800
)

type EthHdr struct {
	dmac      net.HardwareAddr
	smac      net.HardwareAddr
	ethertype uint16
	payload   []byte
}

func (eth_hdr *EthHdr) encode() []byte {
	b := make([]byte, 0)
	b = append(b, eth_hdr.dmac...)
	b = append(b, eth_hdr.smac...)
	b = append(b, writeUint16ToNet(eth_hdr.ethertype)...)

	b = append(b, eth_hdr.payload...)

	return b
}

func (eth_hdr *EthHdr) decode(b []byte) {
	eth_hdr.dmac = b[0:6]
	eth_hdr.smac = b[6:12]
	eth_hdr.ethertype = readUint16FromNet(b[12:14])
	eth_hdr.payload = b[14:]
}

func initEthHdr(header []byte) *EthHdr {
	hdr := &EthHdr{}
	hdr.decode(header)

	return hdr
}
