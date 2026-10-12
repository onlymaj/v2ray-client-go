//go:build grpc

package grpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// Settings that would break the request line or headers are rejected.
func TestNewRejectsInvalidSettings(t *testing.T) {
	for _, s := range []string{
		`{"authority":"a b"}`,
		`{"authority":"a%zz"}`,
		`{"authority":"h\r\nx: y"}`,
		`{"authority":"evil.com/x?"}`,
		`{"authority":"u@h"}`,
		`{"serviceName":"svc\r\nx"}`,
		`{"userAgent":"ua\r\nx: y"}`,
	} {
		if _, err := New([]byte(s)); err == nil {
			t.Errorf("%s: accepted", s)
		}
	}
	if _, err := New([]byte(`{"authority":"[2001:db8::1]:443","serviceName":"/my/path/Tun"}`)); err != nil {
		t.Fatal(err)
	}
}

// An authority that slips past New must fail the dial, not panic.
func TestOpenBadAuthorityNoPanic(t *testing.T) {
	l, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := l.(*Client)
	c.authority = "a%zz"
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go io.Copy(io.Discard, b)
	if _, err := c.Wrap(context.Background(), a); err == nil {
		t.Fatal("Wrap succeeded")
	}
}

// stallReader yields its data, then fails (a server that stops sending).
type stallReader struct{ data []byte }

var errStall = errors.New("stalled")

func (s *stallReader) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, errStall
	}
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}

// A header announcing a maximum-size message must not allocate the whole
// body before it arrives.
func TestReadMessageAllocatesIncrementally(t *testing.T) {
	hdr := []byte{0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr[1:], maxMessage)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range 16 {
		_, err := readMessage(&stallReader{data: append(append([]byte(nil), hdr...), "partial"...)})
		if !errors.Is(err, errStall) {
			t.Fatalf("err %v", err)
		}
	}
	runtime.ReadMemStats(&after)
	if d := after.TotalAlloc - before.TotalAlloc; d > 4<<20 {
		t.Fatalf("16 stalled reads allocated %d bytes", d)
	}
}

func TestReadMessageSizes(t *testing.T) {
	body := bytes.Repeat([]byte{0xAB}, maxMessage)
	msg := append([]byte{0, 0, 0, 0, 0}, body...)
	binary.BigEndian.PutUint32(msg[1:5], maxMessage)
	got, err := readMessage(bytes.NewReader(msg))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("max message: len %d err %v", len(got), err)
	}
	binary.BigEndian.PutUint32(msg[1:5], maxMessage+1)
	if _, err := readMessage(bytes.NewReader(msg)); err == nil {
		t.Fatal("oversized message accepted")
	}
	// Truncated body.
	binary.BigEndian.PutUint32(msg[1:5], 100)
	if _, err := readMessage(bytes.NewReader(msg[:50])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated body: %v", err)
	}
	// Empty message.
	if m, err := readMessage(bytes.NewReader([]byte{0, 0, 0, 0, 0})); err != nil || len(m) != 0 {
		t.Fatalf("empty: %q %v", m, err)
	}
}

// Round 8: with the default 4 MiB HTTP/2 stream window, a stream whose
// reader stalled (a LAN device that stops reading a download) buffered
// 4 MiB. The server must be stopped after about streamWindow.
func TestStalledReaderBuffersOneWindow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var sent atomic.Int64
	h2 := &http2.Server{}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		h2.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			msg := encodeHunk(make([]byte, 16<<10))
			for {
				if _, err := w.Write(msg); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				sent.Add(int64(len(msg)))
			}
		})})
	}()
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	c, err := l.(*Client).DialStream(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Read(make([]byte, 1)); err != nil { // start the call, then stop reading
		t.Fatal(err)
	}
	var last int64 = -1
	for n := sent.Load(); n != last; n = sent.Load() {
		last = n
		time.Sleep(200 * time.Millisecond)
	}
	if last > 2*streamWindow {
		t.Fatalf("server sent %d bytes to a stalled stream, want about %d", last, streamWindow)
	}
}

// Round 9: response headers were limited only by the HTTP/2 default of
// 10 MiB, which a malicious server could make every stream hold.
func TestLargeResponseHeadersRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h2 := &http2.Server{}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		h2.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			for i := range 64 {
				w.Header().Set("X-Pad-"+string(rune('a'+i%26))+string(rune('a'+i/26)), strings.Repeat("x", 4<<10))
			}
			w.WriteHeader(http.StatusOK)
			w.Write(encodeHunk([]byte("hello")))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		})})
	}()
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	c, err := l.(*Client).DialStream(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 5)); err == nil {
		t.Fatal("stream with 256 KiB of response headers was accepted")
	}
}

// Round 10: decodeHunks returned one slice per entry, so a server could send
// a 1 MiB message of 1-byte entries and make the client allocate 41 MB while
// decoding it and pin 8 MB of slice headers until the data was read out.
func TestDecodeHunksNoPerEntryMemory(t *testing.T) {
	msg := bytes.Repeat([]byte{0x0A, 1, 'x'}, maxMessage/3)
	got, err := decodeHunks(msg) // compacts msg in place
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxMessage/3 || &got[0] != &msg[0] {
		t.Fatalf("got %d bytes, want %d inside the message buffer", len(got), maxMessage/3)
	}
}

// Round 13: every stalled stream holds a receive window, and the conn caps
// allow 512 of them: 128 MiB against a 32 MiB heap limit, from four LAN
// addresses that start downloads and stop reading. Only maxStalled streams
// may be stalled at once; one that stalls beyond that is ended.
func TestStalledStreamsCapped(t *testing.T) {
	const after = 50 * time.Millisecond
	oldAfter, oldMax := stallAfter.Swap(int64(after)), maxStalled.Swap(2)
	defer func() { stallAfter.Store(oldAfter); maxStalled.Store(oldMax) }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h2 := &http2.Server{}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		h2.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			msg := encodeHunk(make([]byte, 16<<10))
			for {
				if _, err := w.Write(msg); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		})})
	}()
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	var conns []net.Conn
	for range 3 {
		c, err := l.(*Client).DialStream(context.Background(), func(ctx context.Context) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Read(make([]byte, 1)); err != nil { // start the call, then stop reading
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(10 * after)
	if n := stalled.Load(); n != 2 {
		t.Fatalf("%d streams counted as stalled, want 2", n)
	}
	ended := 0
	buf := make([]byte, 16<<10)
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		for range 8 { // a stream that was cut returns what it had, then the error
			if _, err := c.Read(buf); err != nil {
				if !errors.Is(err, errStalled) {
					t.Fatalf("stream ended with %v", err)
				}
				ended++
				break
			}
		}
	}
	if ended != 1 {
		t.Fatalf("%d streams ended, want only the one that stalled over the cap", ended)
	}
	for _, c := range conns {
		c.Close()
	}
	for i := 0; stalled.Load() != 0 && i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := stalled.Load(); n != 0 {
		t.Fatalf("stalled count is %d after all streams closed", n)
	}
}
