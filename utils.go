package level_ip

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

const Debug = 1

func DPrintf(str string, a ...interface{}) {
	if Debug > 0 {
		log.Printf(str, a...)
	}
	return
}

const (
	_ = iota
	bigEndian
	littleEndian

	INT_SIZE = int(unsafe.Sizeof(0))
)

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctrl", errno)
	}
	return nil
}

func systemEndian() int {
	var testInt int = 0x1
	bs := (*[INT_SIZE]byte)(unsafe.Pointer(&testInt))
	if bs[0] == 0 {
		return littleEndian
	} else {
		return bigEndian
	}
}

func readUint16FromNet(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func readUint32FromNet(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func writeUint16ToNet(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func writeUint32ToNet(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func serializeFrameARP(eth_hdr *EthHdr, arp_hdr *ArpHdr, arpdata *ArpIpv4) []byte {
	buf := make([]byte, 0)

	buf = append(buf, eth_hdr.dmac...)
	buf = append(buf, eth_hdr.smac...)
	buf = append(buf, writeUint16ToNet(eth_hdr.ethertype)...)
	buf = append(buf, writeUint16ToNet(arp_hdr.hwtype)...)
	buf = append(buf, writeUint16ToNet(arp_hdr.protype)...)
	buf = append(buf, arp_hdr.hwsize)
	buf = append(buf, arp_hdr.prosize)
	buf = append(buf, writeUint16ToNet(arp_hdr.opcode)...)
	buf = append(buf, arpdata.smac...)
	buf = append(buf, arpdata.sip...)
	buf = append(buf, arpdata.dmac...)
	buf = append(buf, arpdata.dip...)

	return buf
}

func print_hexdump(data []byte) string {
	ret := ""
	for idx, b := range data {
		if idx > 0 && idx%8 == 0 {
			ret += fmt.Sprintln("")
		}
		ret += fmt.Sprintf("%02x ", b)
	}
	ret += fmt.Sprintln("")

	return ret
}
