// Package netfilter installs the nat PREROUTING rule that REDIRECTs incoming
// TCP to the transparent inbound. It talks to the kernel directly (nf_tables
// over netlink, or legacy x_tables via setsockopt) so the image needs no
// iptables binary.
package netfilter

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Method identifies how the redirect rule was installed.
type Method string

const (
	MethodNFT    Method = "nftables"
	MethodLegacy Method = "iptables-legacy"
)

// Redirect describes the rule: every TCP connection arriving in PREROUTING is
// redirected to Port on the receiving interface's primary address, except
// connections to ExcludeDst (the container's own addresses, so the UI, DNS,
// SOCKS and HTTP ports stay reachable). Only IPv4 addresses are used.
type Redirect struct {
	Port       uint16
	ExcludeDst []netip.Addr
}

// LocalAddrs returns the IPv4 addresses of all non-loopback interfaces, the
// usual ExcludeDst value.
func LocalAddrs() []netip.Addr {
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
			out = append(out, p.Addr())
		}
	}
	return out
}

// Installed is returned by Install; call Remove to delete the rule again.
type Installed struct {
	Method Method
	remove func() error
}

func (i *Installed) Remove() error {
	if i == nil || i.remove == nil {
		return nil
	}
	return i.remove()
}

// Install tries nf_tables first, then legacy x_tables, and returns the first
// method that succeeds. The error lists every attempt when all fail.
func Install(r Redirect) (*Installed, error) {
	var errs []error
	for _, m := range []Method{MethodNFT, MethodLegacy} {
		in, err := InstallWith(m, r)
		if err == nil {
			return in, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", m, err))
	}
	return nil, errors.Join(errs...)
}

// InstallWith installs the rule using one specific method.
func InstallWith(m Method, r Redirect) (*Installed, error) {
	switch m {
	case MethodNFT:
		return installNFT(r)
	case MethodLegacy:
		return installLegacy(r)
	}
	return nil, fmt.Errorf("unknown method %q", m)
}
