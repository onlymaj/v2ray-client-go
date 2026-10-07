//go:build grpc

package grpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestEncodeHunk(t *testing.T) {
	got := encodeHunk([]byte("abc"))
	want := []byte{0, 0, 0, 0, 5, 0x0A, 3, 'a', 'b', 'c'}
	if !bytes.Equal(got, want) {
		t.Fatalf("% x", got)
	}
	// 300-byte payload: two-byte varint length (0xAC 0x02).
	got = encodeHunk(make([]byte, 300))
	if !bytes.Equal(got[:8], []byte{0, 0, 0, 0x01, 0x2F, 0x0A, 0xAC, 0x02}) {
		t.Fatalf("% x", got[:8])
	}
}

func TestDecodeHunks(t *testing.T) {
	// MultiHunk {data: "ab", data: "", data: "c"} plus unknown fields
	// 2 (varint 150) and 3 (bytes "zz").
	msg := []byte{0x0A, 2, 'a', 'b', 0x10, 0x96, 0x01, 0x0A, 0, 0x1A, 2, 'z', 'z', 0x0A, 1, 'c'}
	got, err := decodeHunks(msg)
	if err != nil || len(got) != 2 || string(got[0]) != "ab" || string(got[1]) != "c" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range [][]byte{{0x0A, 5, 'a'}, {0x0A}, {0x0B}, {0x80}} {
		if _, err := decodeHunks(bad); err == nil {
			t.Errorf("% x: want error", bad)
		}
	}
	// Round trip through the framing.
	m, err := readMessage(bytes.NewReader(encodeHunk([]byte("hello"))))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := decodeHunks(m); len(got) != 1 || string(got[0]) != "hello" {
		t.Fatalf("%q", got)
	}
}

func TestPaths(t *testing.T) {
	for _, tc := range []struct {
		name  string
		multi bool
		want  string
	}{
		{"", false, "//Tun"},
		{"svc", false, "/svc/Tun"},
		{"svc", true, "/svc/TunMulti"},
		{"a b", false, "/a%20b/Tun"},
		{"/my/path/Stream", false, "/my/path/Stream"},
		{"/my/path/Stream", true, "/my/path/Stream"},
		{"/my/path/Tun|Multi", true, "/my/path/Multi"},
		{"/my/path/Tun|Multi", false, "/my/path/Tun"},
	} {
		l, _ := New([]byte(fmt.Sprintf(`{"serviceName":%q,"multiMode":%v}`, tc.name, tc.multi)))
		if got := l.(*Client).path; got != tc.want {
			t.Errorf("%q multi=%v: %q, want %q", tc.name, tc.multi, got, tc.want)
		}
	}
}

// gunServer is a cleartext HTTP/2 (prior knowledge) server implementing the
// gun echo: each received entry is echoed back. In multi mode the echo of
// one message is split into two entries of a single MultiHunk.
type gunServer struct {
	ln    net.Listener
	conns atomic.Int32
	path  string
	multi bool
	stall bool // never read the request body
}

func newGunServer(t *testing.T, path string, multi bool) *gunServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &gunServer{ln: ln, path: path, multi: multi}
	h2 := &http2.Server{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go h2.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(s.handle)})
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *gunServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.path || r.Header.Get("Content-Type") != "application/grpc" ||
		r.Header.Get("Te") != "trailers" || r.Host != "example.com" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	if s.stall {
		<-r.Context().Done()
		return
	}
	for {
		m, err := readMessage(r.Body)
		if err != nil {
			break
		}
		entries, _ := decodeHunks(m)
		for _, e := range entries {
			var out []byte
			if s.multi && len(e) > 1 {
				h := len(e) / 2
				body := append([]byte{0x0A}, binary.AppendUvarint(nil, uint64(h))...)
				body = append(body, e[:h]...)
				body = append(body, 0x0A)
				body = binary.AppendUvarint(body, uint64(len(e)-h))
				body = append(body, e[h:]...)
				out = binary.BigEndian.AppendUint32([]byte{0}, uint32(len(body)))
				out = append(out, body...)
			} else {
				out = encodeHunk(e)
			}
			w.Write(out)
			w.(http.Flusher).Flush()
		}
	}
	w.Header().Set("Grpc-Status", "0")
}

func (s *gunServer) dialRaw(calls *atomic.Int32) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		calls.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", s.ln.Addr().String())
	}
}

func echo(t *testing.T, c net.Conn, msg []byte) {
	t.Helper()
	if _, err := c.Write(msg); err != nil {
		t.Error(err)
		return
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(got, msg) {
		t.Error("echo mismatch")
	}
}

func TestSharedConnection(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(fmt.Sprint("multi=", multi), func(t *testing.T) {
			path := "/svc/Tun"
			if multi {
				path = "/svc/TunMulti"
			}
			srv := newGunServer(t, path, multi)
			l, _ := New([]byte(fmt.Sprintf(`{"serviceName":"svc","multiMode":%v,"authority":"example.com"}`, multi)))
			cl := l.(*Client)
			var calls atomic.Int32
			var wg sync.WaitGroup
			for i := range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, err := cl.DialStream(context.Background(), srv.dialRaw(&calls))
					if err != nil {
						t.Error(err)
						return
					}
					defer c.Close()
					echo(t, c, []byte(fmt.Sprintf("stream %d", i)))
					echo(t, c, bytes.Repeat([]byte{byte(i)}, 100000)) // > maxChunk
				}()
			}
			wg.Wait()
			if calls.Load() != 1 || srv.conns.Load() != 1 {
				t.Fatalf("dialRaw calls %d, server conns %d; want 1", calls.Load(), srv.conns.Load())
			}
		})
	}
}

func TestRedialAfterDeadConnection(t *testing.T) {
	srv := newGunServer(t, "/svc/Tun", false)
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	cl := l.(*Client)
	var calls atomic.Int32
	c, err := cl.DialStream(context.Background(), srv.dialRaw(&calls))
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, []byte("one"))
	c.Close()
	cl.raw.Close() // kill the shared connection
	for cl.cc.CanTakeNewRequest() {
		time.Sleep(time.Millisecond) // until the read loop notices
	}
	c, err = cl.DialStream(context.Background(), srv.dialRaw(&calls))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echo(t, c, []byte("two"))
	if calls.Load() != 2 {
		t.Fatalf("dialRaw calls %d, want 2", calls.Load())
	}
}

func TestWrapAndErrors(t *testing.T) {
	srv := newGunServer(t, "/svc/Tun", false)
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	raw, _ := net.Dial("tcp", srv.ln.Addr().String())
	c, err := l.Wrap(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, []byte("wrapped"))
	// Half-close: server finishes with grpc-status 0 and Read sees EOF.
	c.(interface{ CloseWrite() error }).CloseWrite()
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after CloseWrite: %v", err)
	}
	c.Close()

	// Wrong service name: 404 surfaces as an error on Read.
	l, _ = New([]byte(`{"serviceName":"other","authority":"example.com"}`))
	raw, _ = net.Dial("tcp", srv.ln.Addr().String())
	c, _ = l.Wrap(context.Background(), raw)
	defer c.Close()
	c.Write([]byte("x"))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("want error for 404")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
}

func TestReadDeadline(t *testing.T) {
	srv := newGunServer(t, "/svc/Tun", false)
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	var calls atomic.Int32
	c, err := l.(*Client).DialStream(context.Background(), srv.dialRaw(&calls))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Expiry while blocked, and a deadline already in the past.
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("want timeout, got %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("want timeout, got %v", err)
	}
	// Extending the deadline while Read is blocked keeps it waiting.
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	res := make(chan error, 1)
	buf := make([]byte, 2)
	go func() { _, err := io.ReadFull(c, buf); res <- err }()
	c.SetReadDeadline(time.Now().Add(time.Hour))
	time.Sleep(100 * time.Millisecond)
	c.Write([]byte("ok"))
	if err := <-res; err != nil || string(buf) != "ok" {
		t.Fatalf("%q %v", buf, err)
	}
	// Cleared deadline: the stream still works.
	c.SetDeadline(time.Time{})
	echo(t, c, []byte("again"))
}

func TestWriteDeadline(t *testing.T) {
	srv := newGunServer(t, "/svc/Tun", false)
	srv.stall = true
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	var calls atomic.Int32
	c, err := l.(*Client).DialStream(context.Background(), srv.dialRaw(&calls))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// The server never reads, so HTTP/2 flow control eventually blocks.
	c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	chunk := make([]byte, 16<<10)
	for i := 0; ; i++ {
		if _, err := c.Write(chunk); err != nil {
			if !isTimeout(err) {
				t.Fatalf("want timeout, got %v", err)
			}
			break
		}
		if i > 1000 {
			t.Fatal("writes never blocked")
		}
	}
	// Still timed out until the deadline moves; then Write is retried
	// (and blocks again, so use a short deadline).
	if _, err := c.Write(chunk); !isTimeout(err) {
		t.Fatalf("want timeout, got %v", err)
	}
	c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := c.Write(chunk); !isTimeout(err) {
		t.Fatalf("want timeout after extension, got %v", err)
	}
}
