package dispatch

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/onlymaj/v2ray-client-go/internal/netguard"
)

// Destinations a LAN connection may never reach: the container itself and
// the router behind it, plus addresses that are never a valid remote host
// (see netguard.Refused).

var (
	// lookupIP resolves a domain routed direct (a var for tests).
	lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
)

var errRefused = errors.New("dispatch: destination refused")

// refused reports whether ip must not be dialed for a LAN connection.
func refused(ip netip.Addr) bool { return netguard.Refused(ip) }

// resolve returns the first address of host, preferring IPv4.
func resolve(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := lookupIP(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	var v6 netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip, nil
		}
		if !v6.IsValid() {
			v6 = ip
		}
	}
	if !v6.IsValid() {
		return netip.Addr{}, errors.New("dispatch: no address for " + host)
	}
	return v6, nil
}
