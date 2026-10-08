package inbound

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// The CONNECT request line and headers are capped at maxHeader.
func TestHTTPConnectHeaderCap(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	errc := make(chan error, 1)
	go func() {
		_, _, err := httpConnect(a)
		a.Close()
		errc <- err
	}()
	go io.Copy(io.Discard, b)
	b.SetWriteDeadline(time.Now().Add(3 * time.Second))
	b.Write([]byte("CONNECT "))
	chunk := bytes.Repeat([]byte("a"), 1<<10)
	sent := 0
	for ; sent < 1<<20; sent += len(chunk) {
		if _, err := b.Write(chunk); err != nil {
			break
		}
	}
	if sent >= 1<<20 {
		t.Fatal("server read 1 MiB of request line")
	}
	if err := <-errc; err == nil {
		t.Fatal("oversized request accepted")
	}
}

type holdHandler struct{ release chan struct{} }

func (h holdHandler) Handle(c net.Conn, _ netip.AddrPort, _ outbound.Addr, _ bool) {
	<-h.release
	c.Close()
}

// Conns over the per-source limit are closed at once.
func TestConnLimitPerIP(t *testing.T) {
	// Wait for conns of earlier tests to be released.
	for i := 0; ; i++ {
		limits.Lock()
		n := limits.total
		if n == 0 || i == 100 {
			old := maxConnsPerIP
			maxConnsPerIP = 2
			limits.Unlock()
			defer func() { limits.Lock(); maxConnsPerIP = old; limits.Unlock() }()
			break
		}
		limits.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := holdHandler{make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	defer func() { cancel(); <-served }()
	// HTTP CONNECT with a held handler: two get through, the third is cut.
	go func() { ServeHTTP(ctx, ln, h); close(served) }()
	var cs []net.Conn
	for range 3 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("CONNECT x.test:443 HTTP/1.1\r\nHost: x.test:443\r\n\r\n"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		cs = append(cs, c)
	}
	for i, c := range cs[:2] {
		if _, err := c.Read(make([]byte, 64)); err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
	}
	if _, err := cs[2].Read(make([]byte, 64)); err == nil {
		t.Fatal("conn over limit was served")
	}
	close(h.release)
	time.Sleep(50 * time.Millisecond)
	limits.Lock()
	n := limits.total
	limits.Unlock()
	if n != 0 {
		t.Fatalf("limits not released: %d", n)
	}
}

// setLimits waits for conns of earlier tests to be released, then sets the
// limits until the test ends.
func setLimits(t *testing.T, total, perIP int) {
	for i := 0; ; i++ {
		limits.Lock()
		if limits.total == 0 || i == 100 {
			oldT, oldP := maxConns, maxConnsPerIP
			maxConns, maxConnsPerIP = total, perIP
			limits.Unlock()
			t.Cleanup(func() { limits.Lock(); maxConns, maxConnsPerIP = oldT, oldP; limits.Unlock() })
			return
		}
		limits.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
}

// connectFrom opens a CONNECT through the proxy at addr from local address
// src and reports whether it was answered.
func connectFrom(t *testing.T, src, addr string) (net.Conn, bool) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Write([]byte("CONNECT x.test:443 HTTP/1.1\r\nHost: x.test:443\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Read(make([]byte, 64))
	return c, err == nil
}

// With the global cap full, a new source evicts the oldest conn of the
// heaviest source; the heaviest source itself is refused.
func TestConnLimitGlobalEvicts(t *testing.T) {
	setLimits(t, 3, 10)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := holdHandler{make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	defer func() { close(h.release); cancel(); <-served }()
	go func() { ServeHTTP(ctx, ln, h); close(served) }()
	addr := ln.Addr().String()

	var heavy []net.Conn
	for i := range 3 {
		c, ok := connectFrom(t, "127.0.0.1", addr)
		if !ok {
			t.Fatalf("conn %d refused below the cap", i)
		}
		heavy = append(heavy, c)
	}
	if _, ok := connectFrom(t, "127.0.0.1", addr); ok {
		t.Fatal("heaviest source served over the global cap")
	}
	if _, ok := connectFrom(t, "127.0.0.2", addr); !ok {
		t.Fatal("new source refused instead of evicting")
	}
	heavy[0].SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := heavy[0].Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("oldest conn of the heaviest source not evicted: %v", err)
	}
	heavy[1].SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := heavy[1].Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("second conn closed too: %v", err)
	}
	limits.Lock()
	n := limits.total
	limits.Unlock()
	if n != 3 {
		t.Fatalf("total = %d, want 3", n)
	}
}

// IPv6 sources share the per-source cap per /64.
func TestSourceKeyIPv6Prefix(t *testing.T) {
	a := sourceKey(netip.MustParseAddr("2001:db8:1:2:aaaa::1"))
	b := sourceKey(netip.MustParseAddr("2001:db8:1:2:bbbb::2"))
	c := sourceKey(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Fatalf("keys %v %v %v", a, b, c)
	}
	v4 := netip.MustParseAddr("192.0.2.1")
	if sourceKey(netip.AddrFrom16(v4.As16())) != v4 {
		t.Fatal("mapped IPv4 not unmapped")
	}
}
