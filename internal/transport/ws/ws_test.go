//go:build ws

package ws

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// RFC 6455 section 1.3 example.
func TestAcceptKey(t *testing.T) {
	if got := acceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal(got)
	}
}

// readFrame / writeFrame are the minimal server side used by the tests.
func readFrame(t *testing.T, r *bufio.Reader) (byte, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		t.Error(err)
		return 0, nil
	}
	if h[1]&0x80 == 0 {
		t.Error("client frame not masked")
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		io.ReadFull(r, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		io.ReadFull(r, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	var key [4]byte
	io.ReadFull(r, key[:])
	p := make([]byte, n)
	io.ReadFull(r, p)
	for i := range p {
		p[i] ^= key[i&3]
	}
	return h[0] & 0x0F, p
}

func serverFrame(fin bool, op byte, p []byte) []byte {
	b := []byte{op, 0}
	if fin {
		b[0] |= 0x80
	}
	switch {
	case len(p) <= 125:
		b[1] = byte(len(p))
	case len(p) <= 0xFFFF:
		b[1] = 126
		b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	default:
		b[1] = 127
		b = binary.BigEndian.AppendUint64(b, uint64(len(p)))
	}
	return append(b, p...)
}

// echoServer upgrades, then echoes every data frame back split into a
// binary frame + continuation frame, preceded by a ping. A close frame is
// answered with a close frame. Request info is sent on reqs.
func echoServer(t *testing.T, reqs chan<- *http.Request) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs <- r
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptKey(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
		conn.Write([]byte(resp))
		if ed := r.Header.Get("Sec-WebSocket-Protocol"); ed != "" {
			p, _ := base64.RawURLEncoding.DecodeString(ed)
			conn.Write(serverFrame(true, opBinary, p))
		}
		for {
			op, p := readFrame(t, brw.Reader)
			switch op {
			case opClose:
				conn.Write(serverFrame(true, opClose, p))
				return
			case opPong:
				if string(p) != "hi" {
					t.Errorf("pong payload %q", p)
				}
				continue
			case opBinary:
			default:
				t.Errorf("opcode %d", op)
				return
			}
			h := len(p) / 2
			var out []byte
			out = append(out, serverFrame(true, opPing, []byte("hi"))...)
			out = append(out, serverFrame(false, opBinary, p[:h])...)
			out = append(out, serverFrame(true, opContinuation, p[h:])...)
			conn.Write(out)
		}
	}))
}

func dial(t *testing.T, srv *httptest.Server, settings string) net.Conn {
	t.Helper()
	l, err := New([]byte(settings))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := l.Wrap(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEcho(t *testing.T) {
	reqs := make(chan *http.Request, 1)
	srv := echoServer(t, reqs)
	defer srv.Close()
	c := dial(t, srv, `{"path":"tun?x=1","host":"example.com","headers":{"X-Test":"yes"}}`)

	r := <-reqs
	if r.URL.RequestURI() != "/tun?x=1" || r.Host != "example.com" || r.Header.Get("X-Test") != "yes" {
		t.Fatalf("request %s host=%s headers=%v", r.URL, r.Host, r.Header)
	}
	for _, size := range []int{1, 125, 126, 70000} {
		msg := bytes.Repeat([]byte{byte(size)}, size)
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, size)
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("size %d: mismatch", size)
		}
	}
	// Close sends a close frame; the server echoes it and Read returns EOF.
	ws := c.(*Conn)
	ws.writeFrame(opClose, []byte{0x03, 0xE8})
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after close: %v", err)
	}
	c.Close()
}

func TestEarlyData(t *testing.T) {
	reqs := make(chan *http.Request, 1)
	srv := echoServer(t, reqs)
	defer srv.Close()
	c := dial(t, srv, `{"path":"/p?ed=2048"}`)
	defer c.Close()

	if _, err := c.Write([]byte("early")); err != nil {
		t.Fatal(err)
	}
	r := <-reqs
	if r.URL.RequestURI() != "/p" || !strings.HasPrefix(r.Host, "127.0.0.1") {
		t.Fatalf("request %s host=%s", r.URL, r.Host)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "early" {
		t.Fatalf("%q %v", got, err)
	}
	// Later writes go as frames.
	c.Write([]byte("more"))
	got = make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "more" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestEarlyDataTooLarge(t *testing.T) {
	reqs := make(chan *http.Request, 1)
	srv := echoServer(t, reqs)
	defer srv.Close()
	c := dial(t, srv, `{"path":"/?ed=4"}`)
	defer c.Close()

	c.Write([]byte("toolong"))
	if r := <-reqs; r.Header.Get("Sec-WebSocket-Protocol") != "" {
		t.Fatal("early data sent although larger than ed")
	}
	got := make([]byte, 7)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "toolong" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestBadAccept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Sec-WebSocket-Accept", "wrong")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer srv.Close()
	l, _ := New(nil)
	raw, _ := net.Dial("tcp", srv.Listener.Addr().String())
	if _, err := l.Wrap(context.Background(), raw); err == nil {
		t.Fatal("want error")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
}

// A read deadline expiring mid-frame (inside a ping, then inside a data
// frame header) must not corrupt the stream once the deadline is cleared.
func TestReadDeadlineMidFrame(t *testing.T) {
	step := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, _ := w.(http.Hijacker).Hijack()
		defer conn.Close()
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptKey(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"))
		frames := append(serverFrame(true, opPing, []byte("hi")), serverFrame(true, opBinary, []byte("hello"))...)
		for _, part := range [][]byte{frames[:3], frames[3:5], frames[5:]} {
			conn.Write(part)
			<-step
		}
		if op, p := readFrame(t, brw.Reader); op != opPong || string(p) != "hi" {
			t.Errorf("want pong, got %d %q", op, p)
		}
	}))
	defer srv.Close()
	c := dial(t, srv, `{}`)
	defer c.Close()

	buf := make([]byte, 5)
	for range 2 {
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := c.Read(buf); !isTimeout(err) {
			t.Fatalf("want timeout, got %v", err)
		}
		step <- struct{}{}
	}
	c.SetReadDeadline(time.Time{})
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("%q %v", buf, err)
	}
	step <- struct{}{}
}

// With early data, Read before the first Write waits for the handshake and
// must still honour the read deadline.
func TestEarlyDataReadDeadline(t *testing.T) {
	reqs := make(chan *http.Request, 1)
	srv := echoServer(t, reqs)
	defer srv.Close()
	c := dial(t, srv, `{"path":"/?ed=64"}`)
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("want timeout, got %v", err)
	}
	c.SetReadDeadline(time.Time{})
	c.Write([]byte("ok"))
	<-reqs
	got := make([]byte, 2)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ok" {
		t.Fatalf("%q %v", got, err)
	}
}

// Round 8: the handshake deferred to the first Write cleared the conn's
// deadline when it finished, so a deadline the caller had set to bound its
// own Read (the DNS forwarder and the health probe do) was lost and the
// Read could block for ever.
func TestEarlyDataHandshakeKeepsDeadline(t *testing.T) {
	reqs := make(chan *http.Request, 1)
	srv := echoServer(t, reqs)
	defer srv.Close()
	c := dial(t, srv, `{"path":"/?ed=64"}`)
	defer c.Close()

	c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	<-reqs
	got := make([]byte, 2)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ok" {
		t.Fatalf("%q %v", got, err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.Read(got); done <- err }()
	select {
	case err := <-done:
		if !isTimeout(err) {
			t.Fatalf("want timeout, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read ignored the deadline set before the handshake")
	}
}
