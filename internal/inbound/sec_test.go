package inbound

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
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

// With the global cap full, a new source evicts the newest conn of the
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
	if !closed(heavy[2], 2*time.Second) {
		t.Fatal("newest conn of the heaviest source not evicted")
	}
	for _, c := range heavy[:2] {
		if closed(c, 100*time.Millisecond) {
			t.Fatal("older conn of the heaviest source closed too")
		}
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

// closed reports whether c is closed by the peer within d.
func closed(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// Many attacker addresses can neither evict a source within its fair share
// nor kill another host's long-lived conn.
func TestConnLimitFairShare(t *testing.T) {
	setLimits(t, 4, 10)
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

	long, ok := connectFrom(t, "127.0.0.1", addr) // a host's long-lived conn
	if !ok {
		t.Fatal("refused")
	}
	connectFrom(t, "127.0.0.1", addr)
	for range 2 {
		if _, ok := connectFrom(t, "127.0.0.2", addr); !ok {
			t.Fatal("refused below the cap")
		}
	}
	// Full (2+2). Each new attacker address may take a slot only from a
	// source over its share, newest conn first.
	for i := 3; i <= 6; i++ {
		connectFrom(t, fmt.Sprintf("127.0.0.%d", i), addr)
	}
	if closed(long, 200*time.Millisecond) {
		t.Fatal("long-lived conn of a host was evicted")
	}
	// Four sources hold one slot each: at their share, nobody is evicted.
	if _, ok := connectFrom(t, "127.0.0.7", addr); ok {
		t.Fatal("new source served although every source is within its share")
	}
	limits.Lock()
	n := limits.total
	limits.Unlock()
	if n != 4 {
		t.Fatalf("total = %d, want 4", n)
	}
}

// Round 9: a zoned IPv6 literal from SOCKS5 or CONNECT kept its zone, so it
// matched no dest rule (netip.Prefix.Contains is false for zoned addresses)
// and passed the own-address refusal.
func TestAddrDropsZone(t *testing.T) {
	a := addr("fd00::2%x", 80)
	if a.Domain != "" || a.IP != netip.MustParseAddr("fd00::2") {
		t.Fatalf("addr = %+v, want the plain IP fd00::2", a)
	}
	if !netip.MustParsePrefix("fd00::/8").Contains(a.IP) {
		t.Fatal("dest rules would not match the address")
	}
}

// Round 10: an evicted conn left the count at once, but its handler can run
// on for the rest of a dial (10-15 s). A device with five addresses could
// cycle evictions and keep far more handlers and outbound sockets alive than
// maxConns. Evicted conns now stay counted until their handler returns.
func TestEvictedConnsStayCountedUntilReleased(t *testing.T) {
	setLimits(t, 4, 10)
	limits.Lock()
	oldD := maxDraining
	maxDraining = 2
	limits.Unlock()
	defer func() { limits.Lock(); maxDraining = oldD; limits.Unlock() }()
	get := func(ip string) *slot {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		return acquire(a, netip.MustParseAddr(ip))
	}
	var heavy, others []*slot
	for range 4 {
		heavy = append(heavy, get("192.0.2.1"))
	}
	for _, ip := range []string{"192.0.2.2", "192.0.2.3"} {
		s := get(ip)
		if s == nil {
			t.Fatalf("%s refused instead of evicting", ip)
		}
		others = append(others, s)
	}
	if s := get("192.0.2.4"); s != nil {
		t.Fatal("a third eviction went ahead with two evicted handlers still running")
	}
	release(heavy[3]) // an evicted handler returns
	s := get("192.0.2.4")
	if s == nil {
		t.Fatal("eviction still refused after an evicted handler returned")
	}
	for _, s := range append(append(heavy[:3], others...), s) {
		release(s)
	}
	limits.Lock()
	defer limits.Unlock()
	if limits.total != 0 || limits.draining != 0 {
		t.Fatalf("total=%d draining=%d after all released", limits.total, limits.draining)
	}
}

// Round 11: CONNECT accepted host names up to the 8 KB header limit; every
// other name source is capped near 255, and rule matching hashes each
// suffix of the name.
func TestHTTPConnectLongHostRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := holdHandler{make(chan struct{})}
	close(h.release)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	defer func() { cancel(); <-served }()
	go func() { ServeHTTP(ctx, ln, h); close(served) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	host := strings.Repeat("a.", 150) + "test:443"
	c.Write([]byte("CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := c.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 400") {
		t.Fatalf("300-byte CONNECT host answered %q, want 400", buf[:n])
	}
}

// Round 17: the CONNECT request was parsed into a header map, about 15
// times its wire size, held while the head was incomplete: 128 KiB per
// connection for 8 KiB of small headers. The headers are skipped now.
func TestStalledConnectHeadHoldsLittle(t *testing.T) {
	var head strings.Builder
	head.WriteString("CONNECT example.com:443 HTTP/1.1\r\n")
	for i := 0; head.Len() < maxHeader-64; i++ {
		fmt.Fprintf(&head, "%x:\r\n", i)
	}
	const n = 16
	sent := make(chan struct{}, n)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range n {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		go httpConnect(a)
		go func() { b.Write([]byte(head.String())); sent <- struct{}{} }()
	}
	for range n {
		<-sent
	}
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&after)
	if d := int64(after.HeapAlloc) - int64(before.HeapAlloc); d > n*(24<<10) {
		t.Errorf("%d stalled CONNECT heads hold %d bytes, %d each", n, d, d/n)
	}
}

func TestReadRequestHead(t *testing.T) {
	in := "CONNECT h.example:443 HTTP/1.1\r\nX-Long: " + strings.Repeat("a", 6000) + "\r\nHost: other:1\r\n\r\nrest"
	br := bufio.NewReaderSize(strings.NewReader(in), 4096)
	method, target, err := readRequestHead(br)
	if err != nil || method != "CONNECT" || target != "h.example:443" {
		t.Fatalf("%q %q %v", method, target, err)
	}
	if rest, _ := br.Peek(4); string(rest) != "rest" {
		t.Fatalf("bytes after the head: %q", rest)
	}
	for _, bad := range []string{"", "CONNECT h:1\r\n\r\n", "CONNECT h:1 SPDY/3\r\n\r\n", "CONNECT h:1 HTTP/1.1\r\nHost: h\r\n"} {
		if _, _, err := readRequestHead(bufio.NewReader(strings.NewReader(bad))); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}
