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

func initEthHdr(header []byte) EthHdr {
	hdr := EthHdr{
		dmac:    header[0:6],
		smac:    header[6:12],
		payload: header[14:],
	}

	hdr.ethertype = readUint16FromNet(header[12:14])

	return hdr
}
