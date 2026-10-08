//go:build !linux

package inbound

import (
	"errors"
	"net"
	"net/netip"
)

// OriginalDst is only available on Linux.
func OriginalDst(c *net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST: not supported on this OS")
}
