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

// LANBuf is the socket buffer size, in each direction, of a connection
// accepted from the LAN. Left alone, the kernel grows the send buffer to
// tcp_wmem's maximum (4 MiB by default), so a device that stopped reading a
// download had that much queued for it in kernel memory, outside every
// limit counted in this program (round 18). The kernel doubles what is
// asked for and takes no more than wmem_max (208 KiB by default). On
// Ethernet this costs no speed; on Wi-Fi with 20 ms of round-trip time it
// bounds one connection to roughly 80 Mbit/s.
// The sockets to the far side are left to the kernel: a fixed buffer there
// would bound the rate to about buffer / round-trip time.
const LANBuf = 256 << 10

// LANBuffers sets the buffers of an accepted connection.
func LANBuffers(c net.Conn) { SetBuffers(c, LANBuf) }

// SetBuffers sets both socket buffers of c to n bytes.
func SetBuffers(c net.Conn, n int) {
	if t, ok := c.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); ok {
		t.SetReadBuffer(n)
		t.SetWriteBuffer(n)
	}
}

// Direct dials the destination without a proxy.
type Direct struct{ net.Dialer }

func (d *Direct) Dial(ctx context.Context, network string, dest Addr) (net.Conn, error) {
	return d.DialContext(ctx, network, dest.String())
}
