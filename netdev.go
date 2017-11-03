package level_ip

import (
	"net"
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
