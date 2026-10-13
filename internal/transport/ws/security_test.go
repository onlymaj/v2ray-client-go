//go:build ws

package ws

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Settings that would inject into the handshake request are rejected.
func TestNewRejectsInvalidSettings(t *testing.T) {
	for _, s := range []string{
		`{"path":"/ HTTP/1.1\r\nX-Inj: 1\r\n\r\nGET /smuggled"}`,
		`{"path":"/a b"}`,
		`{"path":"/a\u0000"}`,
		`{"host":"h\r\nEvil: yes"}`,
		`{"host":"a b"}`,
		`{"headers":{"X\r\nY":"v"}}`,
		`{"headers":{"X":"v\r\nY: z"}}`,
		`{"headers":{"Host":"h\r\nEvil: yes"}}`,
	} {
		if _, err := New([]byte(s)); err == nil {
			t.Errorf("%s: accepted", s)
		}
	}
	if _, err := New([]byte(`{"path":"ray?ed=2048","host":"ws.example.com:8443","headers":{"X-A":"b c"}}`)); err != nil {
		t.Fatal(err)
	}
}

// A server streaming an endless response header must be cut off at
// maxHandshake instead of growing memory.
func TestHandshakeHeaderLimit(t *testing.T) {
	l, err := New([]byte(`{"path":"/"}`))
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		br := bufio.NewReader(b)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		b.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nX: "))
		chunk := []byte(strings.Repeat("a", 64<<10))
		for i := 0; i < 64; i++ { // 4 MiB
			if _, err := b.Write(chunk); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := l.Wrap(ctx, a); !errors.Is(err, errHandshakeTooLarge) {
		t.Fatalf("err = %v, want %v", err, errHandshakeTooLarge)
	}
}

// Round 17: the handshake response was parsed into a header map, about 15
// times its wire size; a server sending small distinct headers and never
// the blank line made every handshake hold about 1 MiB until the dial
// timeout. Only the two headers the handshake needs are kept now.
func TestStalledHandshakeHoldsLittle(t *testing.T) {
	l, err := New([]byte(`{"path":"/"}`))
	if err != nil {
		t.Fatal(err)
	}
	var head strings.Builder
	head.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	for i := 0; head.Len() < maxHandshake-64; i++ {
		fmt.Fprintf(&head, "%x:\r\n", i)
	}
	const n = 16
	var conns []net.Conn
	done := make(chan struct{}, n)
	sent := make(chan struct{}, n)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range n {
		a, b := net.Pipe()
		conns = append(conns, a, b)
		go func() {
			br := bufio.NewReader(b)
			for {
				if line, err := br.ReadString('\n'); err != nil || line == "\r\n" {
					break
				}
			}
			b.Write([]byte(head.String()))
			sent <- struct{}{}
		}()
		go func() { l.Wrap(context.Background(), a); done <- struct{}{} }()
	}
	for range n {
		<-sent
	}
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&after)
	if d := int64(after.HeapAlloc) - int64(before.HeapAlloc); d > n*(48<<10) {
		t.Errorf("%d stalled handshakes hold %d bytes, %d each", n, d, d/n)
	}
	for _, c := range conns {
		c.Close()
	}
	for range n {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handshake did not end with its connection")
		}
	}
}

func TestReadHandshake(t *testing.T) {
	long := "X-Long: " + strings.Repeat("a", 6000) + "\r\n"
	in := "HTTP/1.1 101 Switching Protocols\r\n" + long + "upgrade: WebSocket\r\nSec-WebSocket-Accept:  abc= \r\n\r\nrest"
	br := bufio.NewReaderSize(strings.NewReader(in), 4096)
	status, upgrade, accept, err := readHandshake(br)
	if err != nil || status != 101 || upgrade != "WebSocket" || accept != "abc=" {
		t.Fatalf("%d %q %q %v", status, upgrade, accept, err)
	}
	if rest, _ := br.Peek(4); string(rest) != "rest" {
		t.Fatalf("bytes after the head: %q", rest)
	}
	for _, bad := range []string{"", "HTTP/1.1\r\n\r\n", "SSH-2.0 101 x\r\n\r\n", "HTTP/1.1 1o1 x\r\n\r\n", "HTTP/1.1 101 x\r\nnocolon\r\n\r\n", "HTTP/1.1 101 x\r\nUpgrade: websocket\r\n"} {
		if _, _, _, err := readHandshake(bufio.NewReader(strings.NewReader(bad))); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// Round 25: a pooled early-data conn that the server had closed (Xray does
// after 4 s without a request) failed in the handshake, which counts as
// "the early data may have been delivered", so a plaintext first payload
// was not sent again and the connection failed. The closed conn is found
// before anything is sent, and that error allows a retry.
func TestDeadPooledConnIsFoundBeforeEarlyData(t *testing.T) {
	a, b := net.Pipe()
	b.Close()
	d := &delayConn{Conn: a, l: &layer{ed: 2048}, dialed: make(chan struct{})}
	_, err := d.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	if err == nil {
		t.Fatal("Write succeeded on a conn the server closed")
	}
	var ed interface{ MayBeDelivered() bool }
	if errors.As(err, &ed) {
		t.Fatalf("%v is marked as possibly delivered; nothing was sent", err)
	}
}
