package level_ip

import (
	"fmt"
	"testing"
)

func handleFrame(dev *NetDev, eth_hdr *EthHdr, ifce *TunInterface) {
	switch eth_hdr.ethertype {
	case ETH_P_ARP:
		arpIncoming(dev, eth_hdr, ifce)
	case ETH_P_IP:
		fmt.Println("Found IPv4")
	default:
	}
}

func TestArp(t *testing.T) {
	dev := netdevInit("10.0.0.4", "00:0c:29:6d:50:25")

	ifce, err := tunInit("")
	if err != nil {
		t.Fatalf("Creating Tap Err: %v\n", err)
	}

	for {
		buf := make([]byte, 100)
		if _, err := ifce.Read(buf); err != nil {
			t.Fatalf("ERR: Read from tun_fd: %v\n", err)
		}
		// DPrintf("Received A Ethernet Frame.\n")
		// print_hexdump(buf)
		eth_hdr := initEthHdr(buf)

		handleFrame(&dev, &eth_hdr, ifce)
	}
}
