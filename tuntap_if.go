package level_ip

import (
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	cIFF_TUN         = 0x0001
	cIFF_TAP         = 0x0002
	cIFF_NOPI        = 0x1000
	cIFF_MULTI_QUEUE = 0x0100
)

type TunTap struct {
	Dev *os.File
}

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

type TunInterface struct {
	isTap bool
	io.ReadWriteCloser
	name string
}

func createInterface(fd uintptr, name string, flags uint16) (createdIFName string, err error) {
	var req ifReq
	req.Flags = flags
	copy(req.Name[:], name)

	err = ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if err != nil {
		return
	}
	createdIFName = strings.Trim(string(req.Name[:]), "\x00")
	return
}

func newTap(name string) (ifce *TunInterface, err error) {
	file, err := os.OpenFile("/dev/net/tap", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var flags uint16
	flags = cIFF_TAP | cIFF_NOPI

	createdName, err := createInterface(file.Fd(), name, flags)
	if err != nil {
		return nil, err
	}
	// optional: setting device options
	// not implemented
	ifce = &TunInterface{name: createdName, isTap: true, ReadWriteCloser: file}
	return
}

func newTun(name string) (ifce *TunInterface, err error) {
	log.Fatal("newTun not implemented")
	return nil, nil
}

func setIfUp(devName string) error {
	cmd := exec.Command("ip", "link", "set", "dev", devName, "up")
	err := cmd.Run()
	return err
}

func setIfRoute(devName string, cidr string) error {
	cmd := exec.Command("ip", "route", "add", "dev", devName, cidr)
	err := cmd.Run()
	return err
}

func tunInit(devName string) (*TunInterface, error) {
	ifce, err := newTap(devName)
	if err != nil {
		return nil, err
	}
	err = setIfUp(ifce.name)
	if err != nil {
		return nil, err
	}
	err = setIfRoute(ifce.name, "10.0.0.0/24")
	if err != nil {
		return nil, err
	}
	return ifce, err
}
