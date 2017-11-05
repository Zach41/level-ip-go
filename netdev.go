package level_ip

import (
	"fmt"
	"net"
	"os"
)

type NetDev struct {
	addr   net.IP           // 4 bytes in our implementation
	hwAddr net.HardwareAddr // 6 bytes in our implementatation
}

// init a netDev from string
func netdevInit(ipString string, hwString string) NetDev {
	ret := NetDev{}
	ret.addr = net.ParseIP(ipString)[12:]
	ret.hwAddr, _ = net.ParseMAC(hwString)

	return ret
}

func (netdev *NetDev) transimit(eth_hdr *EthHdr,
	ethertype uint16,
	dst net.HardwareAddr,
	payloadFrame Frame,
	ifce *TunInterface) {
	copy(eth_hdr.dmac[:], dst)
	copy(eth_hdr.smac[:], netdev.hwAddr)
	eth_hdr.ethertype = ethertype
	eth_hdr.payload = payloadFrame.encode()

	DPrintf("Transimit ETH FRAME\n%s\n", hexdump(eth_hdr.encode()))

	// TODO: Serialize Ethernet Frame
	_, err := ifce.Write(eth_hdr.encode())
	if err != nil {
		fmt.Println("NetDev Transimit Frame Err: ", err)
		os.Exit(1)
	}
}
