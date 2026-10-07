package inbound

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80 // linux/netfilter_ipv4.h

// OriginalDst returns the pre-REDIRECT destination of a TCP connection, read
// with getsockopt(SOL_IP, SO_ORIGINAL_DST) from conntrack.
func OriginalDst(c *net.TCPConn) (netip.AddrPort, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var sa [16]byte // struct sockaddr_in
	var serr error
	err = rc.Control(func(fd uintptr) {
		l := uint32(len(sa))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&sa[0])), uintptr(unsafe.Pointer(&l)), 0)
		if e != 0 {
			serr = e
		}
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if serr != nil {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %w", serr)
	}
	port := binary.BigEndian.Uint16(sa[2:4])
	addr := netip.AddrFrom4([4]byte(sa[4:8]))
	return netip.AddrPortFrom(addr, port), nil
}
