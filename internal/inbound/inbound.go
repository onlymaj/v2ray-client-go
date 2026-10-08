// Package inbound accepts LAN connections (transparent REDIRECT, SOCKS5,
// HTTP CONNECT) and hands each one to a Handler with its destination.
package inbound

import (
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
// them). A conn over either limit is closed at once.
var (
	maxConns      = 2048
	maxConnsPerIP = 256
)

var limits = struct {
	sync.Mutex
	total int
	per   map[netip.Addr]int
}{per: map[netip.Addr]int{}}

func acquire(ip netip.Addr) bool {
	limits.Lock()
	defer limits.Unlock()
	if limits.total >= maxConns || limits.per[ip] >= maxConnsPerIP {
		return false
	}
	limits.total++
	limits.per[ip]++
	return true
}

func release(ip netip.Addr) {
	limits.Lock()
	defer limits.Unlock()
	limits.total--
	if limits.per[ip]--; limits.per[ip] <= 0 {
		delete(limits.per, ip)
	}
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
			if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.EMFILE) {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		ip := srcOf(c).Addr()
		if !acquire(ip) {
			c.Close()
			continue
		}
		go func() {
			defer release(ip)
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
		return outbound.Addr{IP: ip.Unmap(), Port: port}
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
