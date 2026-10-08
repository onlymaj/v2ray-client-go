package inbound

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

type call struct {
	dst   outbound.Addr
	sniff bool
	data  string // first bytes read from the conn
}

// fakeHandler reports the destination and the first line the client sent.
type fakeHandler struct{ ch chan call }

func (h *fakeHandler) Handle(c net.Conn, src netip.AddrPort, dst outbound.Addr, sniff bool) {
	defer c.Close()
	line, _ := bufio.NewReader(c).ReadString('\n')
	h.ch <- call{dst, sniff, line}
}

func start(t *testing.T, serveFn func(context.Context, net.Listener, Handler) error) (string, *fakeHandler) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHandler{ch: make(chan call, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- serveFn(ctx, ln, h) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return ln.Addr().String(), h
}

func dial(t *testing.T, a string) net.Conn {
	c, err := net.Dial("tcp", a)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSOCKS(t *testing.T) {
	a, h := start(t, ServeSOCKS)
	cases := []struct {
		name  string
		req   []byte
		dst   outbound.Addr
		sniff bool
	}{
		{"ipv4", []byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80},
			outbound.Addr{IP: netip.MustParseAddr("1.2.3.4"), Port: 80}, true},
		{"ipv6", append(append([]byte{5, 1, 0, 4}, netip.MustParseAddr("2001:db8::1").AsSlice()...), 1, 187),
			outbound.Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 443}, true},
		{"domain", append(append([]byte{5, 1, 0, 3, 9}, "ex.test.x"...), 1, 187),
			outbound.Addr{Domain: "ex.test.x", Port: 443}, false},
		{"domain ip literal", append(append([]byte{5, 1, 0, 3, 7}, "9.9.9.9"...), 0, 53),
			outbound.Addr{IP: netip.MustParseAddr("9.9.9.9"), Port: 53}, true},
	}
	for _, tc := range cases {
		c := dial(t, a)
		// Greeting, request and early data in one write (pipelining).
		c.Write(append(append([]byte{5, 2, 2, 0}, tc.req...), "hello\n"...))
		if got := readN(t, c, 2); got[0] != 5 || got[1] != 0 {
			t.Fatalf("%s: method reply %v", tc.name, got)
		}
		if got := readN(t, c, 10); got[1] != repSuccess {
			t.Fatalf("%s: reply %v", tc.name, got)
		}
		r := <-h.ch
		if r.dst != tc.dst || r.sniff != tc.sniff || r.data != "hello\n" {
			t.Fatalf("%s: got %+v", tc.name, r)
		}
	}
}

func TestSOCKSRejects(t *testing.T) {
	a, _ := start(t, ServeSOCKS)
	c := dial(t, a)
	c.Write([]byte{5, 1, 2}) // user/pass only
	if got := readN(t, c, 2); got[1] != methodNone {
		t.Fatalf("got %v", got)
	}
	c = dial(t, a)
	c.Write([]byte{5, 1, 0, 5, 3, 0, 1, 1, 2, 3, 4, 0, 53}) // UDP ASSOCIATE
	readN(t, c, 2)
	if got := readN(t, c, 10); got[1] != repCmdNotSupp {
		t.Fatalf("got %v", got)
	}
	c = dial(t, a)
	c.Write([]byte{5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 53}) // BIND
	readN(t, c, 2)
	if got := readN(t, c, 10); got[1] != repCmdNotSupp {
		t.Fatalf("got %v", got)
	}
}

func TestHTTPConnect(t *testing.T) {
	a, h := start(t, ServeHTTP)
	cases := []struct {
		target string
		dst    outbound.Addr
		sniff  bool
	}{
		{"ex.test:443", outbound.Addr{Domain: "ex.test", Port: 443}, false},
		{"1.2.3.4:8443", outbound.Addr{IP: netip.MustParseAddr("1.2.3.4"), Port: 8443}, true},
		{"[2001:db8::1]:443", outbound.Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 443}, true},
	}
	for _, tc := range cases {
		c := dial(t, a)
		c.Write([]byte("CONNECT " + tc.target + " HTTP/1.1\r\nHost: " + tc.target + "\r\n\r\nhello\n"))
		br := bufio.NewReader(c)
		line, _ := br.ReadString('\n')
		if !strings.HasPrefix(line, "HTTP/1.1 200") {
			t.Fatalf("%s: %q", tc.target, line)
		}
		r := <-h.ch
		if r.dst != tc.dst || r.sniff != tc.sniff || r.data != "hello\n" {
			t.Fatalf("%s: got %+v", tc.target, r)
		}
	}
}

func TestHTTPRejects(t *testing.T) {
	a, _ := start(t, ServeHTTP)
	for req, want := range map[string]string{
		"GET http://ex.test/ HTTP/1.1\r\nHost: ex.test\r\n\r\n":         "HTTP/1.1 405",
		"CONNECT ex.test HTTP/1.1\r\nHost: ex.test\r\n\r\n":             "HTTP/1.1 400",
		"CONNECT ex.test:99999 HTTP/1.1\r\nHost: ex.test:99999\r\n\r\n": "HTTP/1.1 400",
	} {
		c := dial(t, a)
		c.Write([]byte(req))
		line, _ := bufio.NewReader(c).ReadString('\n')
		if !strings.HasPrefix(line, want) {
			t.Errorf("%q: got %q, want %s", req, line, want)
		}
	}
}

// A connection made straight to the transparent port (not REDIRECTed) is
// closed without reaching the handler.
func TestTransparentDropsDirect(t *testing.T) {
	a, h := start(t, ServeTransparent)
	c := dial(t, a)
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("direct conn not closed: %d %v", n, err)
	}
	select {
	case r := <-h.ch:
		t.Fatalf("handler called: %+v", r)
	default:
	}
}
