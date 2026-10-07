// Package outbound defines the Dialer interface every proxy protocol
// implements, plus a registry populated by build-tagged init() functions.
package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

// Addr is a proxied destination: either a domain or an IP, plus a port.
type Addr struct {
	Domain string     // set when the destination is a hostname
	IP     netip.Addr // set when the destination is an IP
	Port   uint16
}

func (a Addr) Host() string {
	if a.Domain != "" {
		return a.Domain
	}
	return a.IP.String()
}

func (a Addr) String() string { return net.JoinHostPort(a.Host(), strconv.Itoa(int(a.Port))) }

// Dialer opens a proxied connection to dest. network is "tcp" (UDP is out of
// scope).
type Dialer interface {
	Dial(ctx context.Context, network string, dest Addr) (net.Conn, error)
}

// Factory builds a Dialer from a protocol-specific settings blob (the
// client's JSON config) and a function that opens the underlying transport
// connection to the proxy server.
type Factory func(settings []byte, dialTransport func(ctx context.Context) (net.Conn, error)) (Dialer, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register is called from init() in build-tagged protocol packages.
func Register(protocol string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	factories[protocol] = f
}

func Lookup(protocol string) (Factory, error) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := factories[protocol]
	if !ok {
		return nil, fmt.Errorf("protocol %q not compiled in", protocol)
	}
	return f, nil
}

// Direct dials the destination without a proxy.
type Direct struct{ net.Dialer }

func (d *Direct) Dial(ctx context.Context, network string, dest Addr) (net.Conn, error) {
	return d.DialContext(ctx, network, dest.String())
}
