// Package netfilter installs the nat PREROUTING rule that REDIRECTs incoming
// TCP to the transparent inbound. It talks to the kernel directly (nf_tables
// over netlink, or legacy x_tables via setsockopt) so the image needs no
// iptables binary.
package netfilter

import (
	"errors"
	"fmt"
)

// Method identifies how the redirect rule was installed.
type Method string

const (
	MethodNFT    Method = "nftables"
	MethodLegacy Method = "iptables-legacy"
)

// Redirect describes the rule: every TCP connection arriving in PREROUTING is
// redirected to Port on the receiving interface's primary address.
type Redirect struct {
	Port uint16
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
