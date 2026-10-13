//go:build grpc

package grpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/onlymaj/v2ray-client-go/internal/transport"
	"io"
	"net"
	"net/http"
	"runtime"
	"slices"
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

// floodServer answers every stream with 16 KiB messages for as long as the
// client takes them.
func floodServer(t *testing.T) (dial func(src ...string) net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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
	return func(src ...string) net.Conn {
		ctx := context.Background()
		if len(src) > 0 {
			ctx = transport.WithSource(ctx, src[0])
		}
		c, err := l.(*Client).DialStream(ctx, func(ctx context.Context) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		if _, err := c.Read(make([]byte, 1)); err != nil { // start the call
			t.Fatal(err)
		}
		return c
	}
}

func slowLimits(t *testing.T, window time.Duration, max int32) {
	oldW, oldM := slowWindow.Swap(int64(window)), maxSlow.Swap(max)
	// No hold: the tests of the cap want the oldest slow stream ended at
	// once. TestSlowHold sets it.
	slowMu.Lock()
	oldH := slowHold
	slowHold = 0
	slowMu.Unlock()
	t.Cleanup(func() {
		slowWindow.Store(oldW)
		maxSlow.Store(oldM)
		slowMu.Lock()
		slowHold = oldH
		slowMu.Unlock()
	})
}

// Round 24: with a window of 250 ms a download in a wifi hiccup is listed
// as slow for a moment. The stream ended for a list that is too long was
// the device's oldest slow one, its paused video for example. Only a
// stream slow for slowHold windows is ended that way; before that, the
// newest goes.
func TestSlowHold(t *testing.T) {
	slowLimits(t, 100*time.Millisecond, 2)
	slowMu.Lock()
	slowHold = 50 // 5 s: nothing qualifies during the test
	slowMu.Unlock()
	dial := floodServer(t)
	var conns []net.Conn
	for range 3 {
		conns = append(conns, dial()) // read one byte, then nothing
		time.Sleep(150 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	if n := slowCount(); n != 2 {
		t.Fatalf("%d streams counted as slow, want 2", n)
	}
	buf := make([]byte, 16<<10)
	for i, c := range conns {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var err error
		for range 8 {
			if _, err = c.Read(buf); err != nil {
				break
			}
		}
		if newest := i == len(conns)-1; newest != errors.Is(err, errStalled) {
			t.Fatalf("stream %d ended with %v; want only the newest ended", i, err)
		}
	}
}

func slowCount() int {
	slowMu.Lock()
	defer slowMu.Unlock()
	return len(slowList)
}

// Round 13: every stream whose reader stops holds a receive window, and the
// conn caps allow 512 of them: 128 MiB against a 32 MiB heap limit. Only
// maxSlow streams may be in that state.
// Round 14: the stream that is ended is the one slow for the longest, not
// the newest, so a device cannot hold the slots and have other users'
// paused downloads cut.
func TestSlowStreamsCappedOldestEnded(t *testing.T) {
	slowLimits(t, 100*time.Millisecond, 2)
	dial := floodServer(t)
	var conns []net.Conn
	for range 3 {
		conns = append(conns, dial()) // read one byte, then nothing
		time.Sleep(150 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	if n := slowCount(); n != 2 {
		t.Fatalf("%d streams counted as slow, want 2", n)
	}
	buf := make([]byte, 16<<10)
	for i, c := range conns {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var err error
		for range 8 { // a stream that was ended returns what it had, then the error
			if _, err = c.Read(buf); err != nil {
				break
			}
		}
		if i == 0 && !errors.Is(err, errStalled) {
			t.Fatalf("the stream slow for the longest ended with %v, want errStalled", err)
		}
		if i > 0 && err != nil {
			t.Fatalf("stream %d ended (%v); only the oldest slow one should", i, err)
		}
	}
	for _, c := range conns {
		c.Close()
	}
	for i := 0; slowCount() != 0 && i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := slowCount(); n != 0 {
		t.Fatalf("%d streams still counted as slow after all closed", n)
	}
}

// Round 14: the round-13 cap counted a stream only when one message waited
// 5 s, so a reader taking one message every few seconds was never counted
// and still pinned a full window per stream. Slowness is now judged by how
// much the reader takes while data is waiting. A reader that keeps up is
// never counted.
func TestTrickleReadersCountAsSlow(t *testing.T) {
	slowLimits(t, 100*time.Millisecond, 2)
	dial := floodServer(t)
	stop := make(chan struct{})
	ended := make(chan error, 4)
	for range 4 { // 16 KiB every 150 ms is far below slowFloor
		c := dial()
		go func() {
			buf := make([]byte, 16<<10)
			for {
				select {
				case <-stop:
					ended <- nil
					return
				case <-time.After(150 * time.Millisecond):
				}
				if _, err := c.Read(buf); err != nil {
					ended <- err
					return
				}
			}
		}()
	}
	fast := dial()
	fastErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			select {
			case <-stop:
				fastErr <- nil
				return
			default:
			}
			if _, err := fast.Read(buf); err != nil {
				fastErr <- err
				return
			}
		}
	}()
	time.Sleep(1500 * time.Millisecond)
	if n := slowCount(); n > 2 {
		t.Fatalf("%d streams counted as slow, cap is 2", n)
	}
	close(stop)
	cut := 0
	for range 4 {
		if err := <-ended; errors.Is(err, errStalled) {
			cut++
		} else if err != nil {
			t.Fatalf("trickle stream ended with %v", err)
		}
	}
	if cut < 2 {
		t.Fatalf("%d trickle streams ended, want at least the 2 over the cap", cut)
	}
	if err := <-fastErr; err != nil {
		t.Fatalf("a reader that keeps up was ended: %v", err)
	}
}

func hunksOf(t *testing.T, msg []byte) (pieces [][]byte, err error) {
	t.Helper()
	err = readHunks(bufio.NewReader(bytes.NewReader(msg)), func(p []byte) error {
		pieces = append(pieces, p)
		return nil
	})
	return pieces, err
}

func grpcFrame(body []byte) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(body))), body...)
}

// Round 14: the client assembled each message whole before handing it to
// the reader, so a server could make every stream hold a 1 MiB buffer (and a
// second one waiting behind a slow reader). Messages are now decoded as they
// arrive, in pieces of at most readStep.
func TestReadHunksStreams(t *testing.T) {
	// MultiHunk {data: "ab", data: "", data: "c"} plus unknown fields 2
	// (varint 150) and 3 (bytes "zz").
	got, err := hunksOf(t, grpcFrame([]byte{0x0A, 2, 'a', 'b', 0x10, 0x96, 0x01, 0x0A, 0, 0x1A, 2, 'z', 'z', 0x0A, 1, 'c'}))
	if err != nil || string(bytes.Join(got, nil)) != "abc" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range [][]byte{{0x0A, 5, 'a'}, {0x0A}, {0x0B}, {0x80}} {
		if _, err := hunksOf(t, grpcFrame(bad)); err == nil {
			t.Errorf("% x: want error", bad)
		}
	}
	if _, err := hunksOf(t, nil); err != io.EOF {
		t.Fatalf("empty stream: %v, want io.EOF", err)
	}
	// A full-size message of 1-byte entries: joined into few pieces (round
	// 10), none over readStep.
	got, err = hunksOf(t, grpcFrame(bytes.Repeat([]byte{0x0A, 1, 'x'}, maxMessage/3)))
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, p := range got {
		if len(p) > readStep {
			t.Fatalf("piece of %d bytes, limit %d", len(p), readStep)
		}
		total += len(p)
	}
	if total != maxMessage/3 || len(got) > maxMessage/3/readStep+2 {
		t.Fatalf("%d bytes in %d pieces", total, len(got))
	}
	// One big hunk arrives as pieces while the rest is still on the wire.
	big := append([]byte{0x0A}, binary.AppendUvarint(nil, 200<<10)...)
	big = append(big, make([]byte, 200<<10)...)
	first := 0
	err = readHunks(bufio.NewReader(bytes.NewReader(grpcFrame(big)[:100<<10])), func(p []byte) error {
		first += len(p)
		return nil
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) || first < 64<<10 {
		t.Fatalf("truncated big hunk: %d bytes delivered before %v", first, err)
	}
	over := grpcFrame(nil)
	binary.BigEndian.PutUint32(over[1:], maxMessage+1)
	if _, err := hunksOf(t, over); err == nil {
		t.Fatal("message over maxMessage accepted")
	}
}

// Round 14: the HTTP/2 client keeps an upload buffer of the server's
// SETTINGS_MAX_FRAME_SIZE (up to 512 KiB) per stream for the life of the
// tunnel. Go's own HTTP/2 server advertises 1 MiB. The value is rewritten
// to 16384 on the way in.
func TestGuardConnClampsMaxFrameSize(t *testing.T) {
	settings := []byte{0, 0, 18, 4, 0, 0, 0, 0, 0,
		0, 3, 0, 0, 0, 100, // MAX_CONCURRENT_STREAMS 100
		0, 5, 0, 0x10, 0, 0, // MAX_FRAME_SIZE 1 MiB
		0, 4, 0, 0x10, 0, 0} // INITIAL_WINDOW_SIZE 1 MiB
	data := []byte{0, 0, 6, 0, 0, 0, 0, 0, 1, 0, 5, 0, 0x10, 0, 0} // DATA that looks like a setting
	ack := []byte{0, 0, 0, 4, 1, 0, 0, 0, 0}
	late := []byte{0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 5, 0, 0xff, 0xff, 0xff}
	in := slices.Concat(settings, data, ack, late)
	want := slices.Clone(in)
	copy(want[9+6+2:], []byte{0, 0, 0x40, 0})
	copy(want[len(want)-4:], []byte{0, 0, 0x40, 0})
	for _, step := range []int{1, 2, 7, len(in)} {
		g := &guardConn{}
		got := slices.Clone(in)
		for i := 0; i < len(got); i += step {
			g.scan(got[i:min(i+step, len(got))])
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("step %d:\n got % x\nwant % x", step, got, want)
		}
	}
}

// stallConn stops reading when stall is closed.
type stallConn struct {
	net.Conn
	stall, release chan struct{}
}

func (c *stallConn) Read(p []byte) (int, error) {
	select {
	case <-c.stall:
		<-c.release
		return 0, io.EOF
	default:
	}
	return c.Conn.Read(p)
}

// Round 14: a server that granted large windows and then stopped reading
// its socket blocked one writer for ever with the connection's write lock
// held; every later tunnel was handed out on that connection and hung.
// A write that makes no progress now ends the connection, and the next
// tunnel dials a new one.
func TestStalledServerConnIsReplaced(t *testing.T) {
	old := writeTimeout.Swap(int64(300 * time.Millisecond))
	defer writeTimeout.Store(old)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	stall, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	h2 := &http2.Server{MaxUploadBufferPerConnection: 256 << 20, MaxUploadBufferPerStream: 256 << 20}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h2.ServeConn(&stallConn{Conn: c, stall: stall, release: release}, &http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					io.Copy(io.Discard, r.Body)
				})})
		}
	}()
	var dials atomic.Int32
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	cl := l.(*Client)
	dial := func() net.Conn {
		c, err := cl.DialStream(context.Background(), func(ctx context.Context) (net.Conn, error) {
			dials.Add(1)
			return net.Dial("tcp", ln.Addr().String())
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	c := dial()
	if _, err := c.Write(make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	close(stall) // the server stops reading
	wrote := make(chan error, 1)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			if _, err := c.Write(buf); err != nil {
				wrote <- err
				return
			}
		}
	}()
	select {
	case <-wrote:
	case <-time.After(10 * time.Second):
		t.Fatal("writes to a server that stopped reading never failed")
	}
	time.Sleep(200 * time.Millisecond) // let the client notice the closed conn
	dial()
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d connections dialed, want a second one after the first wedged", n)
	}
}

// Round 15: one read that found the reader waiting restarted the window, so
// a reader that stalled for most of it and then took a few pieces in a
// burst was never counted, at a fraction of slowFloor.
func TestBurstReadersCountAsSlow(t *testing.T) {
	slowLimits(t, 400*time.Millisecond, 2)
	dial := floodServer(t)
	stop := make(chan struct{})
	ended := make(chan error, 4)
	for range 4 { // 48 KiB every 350 ms, about 137 KiB/s, waiting 90% of the time
		c := dial()
		go func() {
			buf := make([]byte, 16<<10)
			for {
				select {
				case <-stop:
					ended <- nil
					return
				case <-time.After(350 * time.Millisecond):
				}
				for range 3 {
					if _, err := c.Read(buf); err != nil {
						ended <- err
						return
					}
				}
			}
		}()
	}
	time.Sleep(2500 * time.Millisecond)
	if n := slowCount(); n > 2 {
		t.Fatalf("%d streams counted as slow, cap is 2", n)
	}
	close(stop)
	cut := 0
	for range 4 {
		if err := <-ended; errors.Is(err, errStalled) {
			cut++
		} else if err != nil {
			t.Fatalf("burst stream ended with %v", err)
		}
	}
	if cut < 2 {
		t.Fatalf("%d burst streams ended, want at least the 2 over the cap", cut)
	}
}

// Round 15: the stream ended was the oldest slow one of any device, so a
// device opening many stalled downloads had another device's paused
// download cut. The device with the most slow streams loses its own.
func TestSlowCapEndsStreamOfBusiestSource(t *testing.T) {
	slowLimits(t, 100*time.Millisecond, 3)
	dial := floodServer(t)
	phone := dial("192.168.88.10") // slow for the longest
	time.Sleep(150 * time.Millisecond)
	var hog []net.Conn
	for range 3 {
		hog = append(hog, dial("192.168.88.66"))
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	if n := slowCount(); n != 3 {
		t.Fatalf("%d streams counted as slow, want 3", n)
	}
	ends := func(c net.Conn) error {
		buf := make([]byte, 16<<10)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var err error
		for range 8 { // a stream that was ended returns what it had, then the error
			if _, err = c.Read(buf); err != nil {
				break
			}
		}
		return err
	}
	if err := ends(phone); err != nil {
		t.Fatalf("the other device's stream ended: %v", err)
	}
	if err := ends(hog[0]); !errors.Is(err, errStalled) {
		t.Fatalf("the busiest device's oldest slow stream ended with %v, want errStalled", err)
	}
	for i, c := range hog[1:] {
		if err := ends(c); err != nil {
			t.Fatalf("hog stream %d ended (%v); only one stream is over the cap", i+1, err)
		}
	}
}

// stuckReader returns its bytes and then nothing, like a server that stops
// sending mid-message. Reading past the end fails the test's wait.
type stuckReader struct {
	b    []byte
	done chan struct{}
}

func (r *stuckReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		close(r.done)
		select {}
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// Round 15: the header of a message and the two bytes that open a hunk
// made readHunks allocate a full 32 KiB piece before any payload arrived;
// 512 streams held 16 MiB for 8 bytes each, outside the slow-reader cap.
func TestHunkHeaderAloneAllocatesLittle(t *testing.T) {
	msg := append([]byte{0x0A}, binary.AppendUvarint(nil, 512<<10)...)
	head := grpcFrame(append(msg, make([]byte, 512<<10)...))[:5+len(msg)+10] // and 10 bytes of payload
	const n = 16
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range n {
		r := &stuckReader{b: head, done: make(chan struct{})}
		go readHunks(bufio.NewReaderSize(r, 4<<10), func([]byte) error { return nil })
		<-r.done
	}
	time.Sleep(50 * time.Millisecond)
	runtime.ReadMemStats(&after)
	if d := after.TotalAlloc - before.TotalAlloc; d > n*(12<<10) {
		t.Fatalf("%d stuck hunk headers allocated %d bytes", n, d)
	}
}

type closeSpy struct {
	net.Conn
	closed *atomic.Int32
}

func (c closeSpy) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

// Round 16: the shared HTTP/2 connection had no idle timeout, so one health
// probe left a TLS and HTTP/2 connection open (and pinging) for ever on
// every gRPC client, 1000 of them from one subscription.
func TestIdleSharedConnIsClosed(t *testing.T) {
	old := idleTimeout.Swap(int64(200 * time.Millisecond))
	defer idleTimeout.Store(old)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h2 := &http2.Server{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h2.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				io.Copy(io.Discard, r.Body)
			})})
		}
	}()
	var dials, closed atomic.Int32
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	cl := l.(*Client)
	defer cl.Close()
	probe := func() {
		c, err := cl.DialStream(context.Background(), func(ctx context.Context) (net.Conn, error) {
			dials.Add(1)
			raw, err := net.Dial("tcp", ln.Addr().String())
			return closeSpy{raw, &closed}, err
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	probe()
	probe() // within the idle time: same connection
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d dials for two probes in a row, want 1", n)
	}
	for i := 0; closed.Load() == 0 && i < 300; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if closed.Load() == 0 {
		t.Fatal("idle shared connection still open after 3 s")
	}
	// Round 18: the closed connection is also let go of, not kept until
	// the next dial.
	cl.mu.Lock()
	held := cl.cc != nil || cl.raw != nil || cl.idle != nil || cl.streams != 0
	cl.mu.Unlock()
	if held {
		t.Fatal("client still refers to the connection it closed")
	}
	probe()
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials, want 2 (a new connection after the idle one closed)", n)
	}
}

// Round 19: the HTTP/2 transport added "accept-encoding: gzip" to the
// tunnel request and would have inflated a reply marked as gzip. A gRPC
// client sends no such header.
func TestTunnelRequestDoesNotAskForGzip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	h2 := &http2.Server{}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		h2.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got <- r.Header.Get("Accept-Encoding")
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			io.Copy(io.Discard, r.Body)
		})})
	}()
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	cl := l.(*Client)
	defer cl.Close()
	c, err := cl.DialStream(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x"))
	select {
	case ae := <-got:
		if ae != "" {
			t.Fatalf("accept-encoding %q sent", ae)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no request")
	}
}

// h2Echo serves gRPC-looking tunnels that echo, with the given stream
// limit, and counts the connections it accepted.
func h2Echo(t *testing.T, maxStreams uint32) (addr string, conns *atomic.Int32) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	conns = new(atomic.Int32)
	h2 := &http2.Server{MaxConcurrentStreams: maxStreams}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go h2.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				buf := make([]byte, 4096)
				for {
					n, err := r.Body.Read(buf)
					if n > 0 {
						w.Write(buf[:n])
						w.(http.Flusher).Flush()
					}
					if err != nil {
						return
					}
				}
			})})
		}
	}()
	return ln.Addr().String(), conns
}

// Round 21: a connection lingers for idleTimeout after its last tunnel,
// and that includes the one tunnel of a health probe. Nothing bounded how
// many did at once: a subscription of 1000 gRPC servers probed in turn had
// hundreds of TLS and HTTP/2 connections open with no traffic.
func TestIdleConnsAreBoundedOverAllClients(t *testing.T) {
	old := maxIdleConns
	maxIdleConns = 2
	defer func() { maxIdleConns = old }()
	addr, _ := h2Echo(t, 100)
	const clients = 6
	var cls []*Client
	for i := range clients {
		l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
		cl := l.(*Client)
		defer cl.Close()
		cls = append(cls, cl)
		c, err := cl.DialStream(context.Background(), func(ctx context.Context) (net.Conn, error) {
			return net.Dial("tcp", addr)
		})
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 { // with and without a byte sent
			if _, err := c.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		c.Close() // a probe: one tunnel, then none
	}
	open := func() (n int) {
		for _, cl := range cls {
			cl.mu.Lock()
			if cl.cc != nil {
				n++
			}
			cl.mu.Unlock()
		}
		return n
	}
	for i := 0; open() > maxIdleConns && i < 300; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	idleSet.Lock()
	listed := len(idleSet.list)
	idleSet.Unlock()
	if n := open(); n != maxIdleConns || listed != maxIdleConns {
		t.Fatalf("%d of %d clients still hold a connection, %d listed as idle; want %d", n, clients, listed, maxIdleConns)
	}
}

// Round 21: a server that allows one stream per connection got a TLS and
// HTTP/2 connection for every tunnel, without limit. Round 22: the bound
// refused new tunnels, which locked out a client whose server retires
// connections with GOAWAY; a replaced connection is closed instead.
func TestServerWithOneStreamPerConnIsBounded(t *testing.T) {
	setMaxDraining(t, 7)
	addr, _ := h2Echo(t, 1)
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	cl := l.(*Client)
	defer cl.Close()
	dial := func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", addr) }
	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	const extra = 3
	for i := 0; i < maxDraining+1+extra; i++ {
		c, err := cl.DialStream(context.Background(), dial)
		if err != nil {
			t.Fatalf("tunnel %d: %v", i, err)
		}
		open = append(open, c)
		// A round trip, so the server's stream limit has arrived.
		if err := echoOnce(c); err != nil {
			t.Fatalf("tunnel %d: %v", i, err)
		}
	}
	if n := drainLen(); n > maxDraining {
		t.Fatalf("%d replaced connections still open, want at most %d", n, maxDraining)
	}
	for i, c := range open {
		err := echoOnce(c)
		if old := i < extra; old != (err != nil) {
			t.Fatalf("tunnel %d of %d: err %v, want the oldest %d ended and the rest alive", i, len(open), err, extra)
		}
	}
}

func setMaxDraining(t *testing.T, n int) {
	old := maxDraining
	maxDraining = n
	t.Cleanup(func() {
		maxDraining = old
		drainSet.Lock()
		drainSet.list = nil
		drainSet.Unlock()
	})
}

func drainLen() int {
	drainSet.Lock()
	defer drainSet.Unlock()
	return len(drainSet.list)
}

func echoOnce(c net.Conn) error {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, 1))
	return err
}

// Round 22: the bound on replaced connections was per client and closed
// the oldest. A LAN device that parked one tunnel on each replaced
// connection had the oldest ones closed, with the long-lived tunnels of
// other devices on them. The connection closed is now one of the device
// that holds the most of them, and one it does not share if there is one.
func TestParkedTunnelsCostTheirOwner(t *testing.T) {
	setMaxDraining(t, 3)
	addr, _ := h2Echo(t, 2)
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	cl := l.(*Client)
	defer cl.Close()
	dial := func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", addr) }
	open := func(src string) net.Conn {
		t.Helper()
		c, err := cl.DialStream(transport.WithSource(context.Background(), src), dial)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		if err := echoOnce(c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	victim := open("victim") // on the first connection, which is the oldest
	var parked []net.Conn
	// Two tunnels fill a connection; the next dial replaces it.
	for range 2*(maxDraining+2) - 1 {
		parked = append(parked, open("parker"))
	}
	if n := drainLen(); n > maxDraining {
		t.Fatalf("%d replaced connections, want at most %d", n, maxDraining)
	}
	if err := echoOnce(victim); err != nil {
		t.Fatalf("the other device's tunnel was cut: %v", err)
	}
	cut := 0
	for _, c := range parked {
		if echoOnce(c) != nil {
			cut++
		}
	}
	if cut != 2 {
		t.Fatalf("%d of the parker's tunnels were cut, want the 2 on one connection", cut)
	}
}

// Round 23: with 32 replaced connections kept, a device that held nothing
// (it opened short tunnels until the connection was retired, and closed
// them) had the long-lived tunnels of other devices cut, one connection
// per retirement. Replaced connections are bounded by the tunnels on them,
// so none is closed for being one too many.
func TestRetiringConnectionsCutsNobody(t *testing.T) {
	addr, _ := h2Echo(t, 2)
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	cl := l.(*Client)
	defer cl.Close()
	dial := func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", addr) }
	open := func(src string) net.Conn {
		t.Helper()
		c, err := cl.DialStream(transport.WithSource(context.Background(), src), dial)
		if err != nil {
			t.Fatal(err)
		}
		if err := echoOnce(c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for range 40 {
		held = append(held, open("victim"))
		a := open("pusher") // the connection is full
		b := open("pusher") // and is replaced
		a.Close()
		b.Close()
		// The next round starts on a connection of its own.
		for i := 0; ; i++ {
			cl.mu.Lock()
			n := cl.streams
			cl.mu.Unlock()
			if n == 0 {
				break
			}
			if i == 300 {
				t.Fatal("the pusher's tunnel did not end")
			}
			time.Sleep(10 * time.Millisecond)
		}
		cl.Close() // let go of the empty connection; the replaced ones stay
		cl.mu.Lock()
		cl.closed = false
		cl.mu.Unlock()
	}
	for i, c := range held {
		if err := echoOnce(c); err != nil {
			t.Fatalf("long-lived tunnel %d was cut: %v", i, err)
		}
	}
}

// Round 22: a tunnel that had reserved a connection's last stream could be
// failed by the next dial, which found the connection full and shut it
// down before the stream had started.
func TestLastStreamSurvivesTheNextDial(t *testing.T) {
	addr, _ := h2Echo(t, 2)
	dial := func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", addr) }
	for round := range 10 {
		l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
		cl := l.(*Client)
		first, err := cl.DialStream(context.Background(), dial)
		if err != nil {
			t.Fatal(err)
		}
		if err := echoOnce(first); err != nil { // the stream limit has arrived
			t.Fatal(err)
		}
		last, err := cl.DialStream(context.Background(), dial)
		if err != nil {
			t.Fatal(err)
		}
		next, err := cl.DialStream(context.Background(), dial)
		if err != nil {
			t.Fatal(err)
		}
		if err := echoOnce(last); err != nil {
			t.Fatalf("round %d: the tunnel on the last stream failed: %v", round, err)
		}
		first.Close()
		last.Close()
		next.Close()
		cl.Close()
	}
}

// Round 23: a stream was first judged 2 s after its first data, so a
// device that replaced its stalled streams every two seconds was never
// counted and held a window for each: 23 MiB with 64 streams. Round 24: a
// shorter first window alone was passed by a reader that took 96 KiB and
// then stalled. Every window is short now.
func TestStalledReaderIsCountedEarly(t *testing.T) {
	slowLimits(t, time.Duration(slowWindow.Load()), 8)
	dial := floodServer(t)
	never := dial() // read one byte, then nothing
	defer never.Close()
	started := dial()
	defer started.Close()
	started.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(started, make([]byte, 96<<10)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(900 * time.Millisecond)
	if n := slowCount(); n != 2 {
		t.Fatalf("%d streams counted as slow 0.9 s after their readers stopped, want 2", n)
	}
}

// Round 23: without a connection window (the default is 1 GiB) every young
// stream could hold its own window. Round 24: the first test of this only
// compared two constants. The client announces the window in its first
// WINDOW_UPDATE on stream 0 (RFC 9113 section 6.9).
func TestConnWindowIsAnnounced(t *testing.T) {
	if connWindow <= int(maxSlow.Load())*streamWindow {
		t.Fatalf("connWindow %d must be above maxSlow windows (%d), or the slow streams that are allowed stop the others", connWindow, int(maxSlow.Load())*streamWindow)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan uint32, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(c, preface); err != nil {
			return
		}
		fr := http2.NewFramer(c, c)
		fr.WriteSettings()
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if wu, ok := f.(*http2.WindowUpdateFrame); ok && wu.StreamID == 0 {
				got <- wu.Increment
				return
			}
		}
	}()
	l, _ := New([]byte(`{"serviceName":"svc","authority":"example.com"}`))
	cl := l.(*Client)
	defer cl.Close()
	c, err := cl.DialStream(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case inc := <-got:
		// The window starts at 65535; the update raises it to connWindow.
		if int(inc) != connWindow && int(inc)+65535 != connWindow {
			t.Fatalf("connection window update of %d, want %d", inc, connWindow)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no WINDOW_UPDATE for the connection")
	}
}
