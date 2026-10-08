package inbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
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
