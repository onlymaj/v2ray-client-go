// Package inbound accepts LAN connections (transparent REDIRECT, SOCKS5,
// HTTP CONNECT) and hands each one to a Handler with its destination.
package inbound

import (
	"container/list"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// Handler serves one connection and closes it. dispatch.Dispatcher
// satisfies it. sniff asks the handler to peek the first bytes for a
// domain; a dst.Domain already set is used as is.
type Handler interface {
	Handle(conn net.Conn, src netip.AddrPort, dst outbound.Addr, sniff bool)
}

const handshakeTimeout = 10 * time.Second

// Open connection limits shared by every inbound (vars so tests can lower
// them). maxConns is sized for GOMEMLIMIT=32MiB beside config.MaxClients.
// Measured after round 21 on amd64, heap and stacks per relayed conn that
// is idle: 19 KB direct, 59-72 KB for VLESS over TLS, Reality, WebSocket or
// gRPC, 87-95 KB for VMess; 70-100 KB once it has carried a large
// download; up to 115 KB when both directions wait with the large copy
// buffer. 256 conns are then 15-26 MB, and 29 MB in the worst case, which
// with the clients' share does not fit and leans on the collector. Sources
// are counted per IPv4 address and per IPv6 /64, so privacy addresses
// don't multiply the per-source cap.
//
// When the global cap is full, a new conn from a source below its fair
// share (maxConns / active sources, the new source included) evicts the
// newest conn of the source holding the most slots, if that source holds
// more than its fair share; otherwise the new conn is closed at once. A
// few LAN hosts can then never lock everyone else out, and a host with
// many addresses can neither evict a host within its share nor kill
// anyone's long-lived conns: only the newest conns of an over-share source
// go.
//
// An evicted conn's handler can outlive it (a dial in progress runs up to
// 15 s before it sees the closed conn), so it stays counted as draining
// until the handler returns, and nothing more is evicted while maxDraining
// handlers are in that state. Handlers never exceed maxConns + maxDraining.
var (
	maxConns      = 256
	maxConnsPerIP = 64
	maxDraining   = 32
)

var limits = struct {
	sync.Mutex
	total    int
	draining int                       // evicted conns whose handler has not returned yet
	per      map[netip.Addr]*list.List // source key -> its *slot, oldest first
}{per: map[netip.Addr]*list.List{}}

// slot is one open conn counted against the limits.
type slot struct {
	conn    net.Conn
	key     netip.Addr
	el      *list.Element
	evicted bool
}

// sourceKey is the unit the per-source cap counts: the IPv4 address, or the
// /64 of an IPv6 address.
func sourceKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}

// acquire counts c from ip against the limits, evicting another source's
// oldest conn if the global cap is full (see maxConns). It returns nil if
// c must be refused.
func acquire(c net.Conn, ip netip.Addr) *slot {
	key := sourceKey(ip)
	var victim net.Conn
	defer func() {
		if victim != nil {
			victim.Close()
		}
	}()
	limits.Lock()
	defer limits.Unlock()
	n := 0
	if l := limits.per[key]; l != nil {
		n = l.Len()
	}
	if n >= maxConnsPerIP {
		return nil
	}
	if limits.total >= maxConns {
		active := len(limits.per)
		if n == 0 {
			active++
		}
		share := maxConns / active
		var heavy *list.List
		for k, l := range limits.per {
			if k != key && (heavy == nil || l.Len() > heavy.Len()) {
				heavy = l
			}
		}
		if n >= share || heavy == nil || heavy.Len() <= share || limits.draining >= maxDraining {
			return nil
		}
		old := heavy.Back().Value.(*slot)
		old.evicted = true
		removeLocked(old)
		limits.draining++
		victim = old.conn
	}
	l := limits.per[key]
	if l == nil {
		l = list.New()
		limits.per[key] = l
	}
	s := &slot{conn: c, key: key}
	s.el = l.PushBack(s)
	limits.total++
	return s
}

func release(s *slot) {
	limits.Lock()
	defer limits.Unlock()
	if s.evicted {
		limits.draining--
	} else {
		removeLocked(s)
	}
}

func removeLocked(s *slot) {
	l := limits.per[s.key]
	l.Remove(s.el)
	if l.Len() == 0 {
		delete(limits.per, s.key)
	}
	limits.total--
}

// serve accepts until ctx is done or ln is closed, running handle for each
// conn in its own goroutine. It returns nil when stopped by ctx.
func serve(ctx context.Context, ln net.Listener, handle func(net.Conn)) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
				errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		s := acquire(c, srcOf(c).Addr())
		if s == nil {
			c.Close()
			continue
		}
		outbound.LANBuffers(c)
		go func() {
			defer release(s)
			handle(c)
		}()
	}
}

func srcOf(c net.Conn) netip.AddrPort {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

// addr builds a destination from a host string (IP literal or domain).
func addr(host string, port uint16) outbound.Addr {
	if ip, err := netip.ParseAddr(host); err == nil {
		// Without the zone: "fd00::2%x" is the address fd00::2, but with
		// the zone kept it equals no address and lies in no prefix, so it
		// would pass the own-address refusal and every dest rule.
		return outbound.Addr{IP: ip.WithZone("").Unmap(), Port: port}
	}
	return outbound.Addr{Domain: host, Port: port}
}

// prefixConn replays bytes already buffered by a reader before reading
// from the conn.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
