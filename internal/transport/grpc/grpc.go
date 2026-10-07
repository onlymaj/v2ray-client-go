//go:build grpc

// Package grpc is a client for Xray's "gun" gRPC transport
// (transport/internet/grpc) built directly on golang.org/x/net/http2,
// without grpc-go or protobuf.
//
// Each tunnel is one bidirectional-streaming call:
//
//	POST /<serviceName>/Tun        (or /TunMulti in multiMode)
//	content-type: application/grpc, te: trailers
//
// and both bodies are sequences of gRPC Length-Prefixed-Messages
// (gRPC PROTOCOL-HTTP2.md): 1 byte compressed flag (always 0), 4 byte
// big-endian length, then a protobuf message. The messages are Xray's
// encoding/stream.proto:
//
//	message Hunk      { bytes data = 1; }
//	message MultiHunk { repeated bytes data = 1; }
//
// Both encode as one or more "0x0A <varint len> <bytes>" fields, so a
// single decoder handles both; writes always send a single entry.
//
// Many tunnels share one HTTP/2 connection (Xray dial.go keeps one
// grpc.ClientConn per destination in globalDialerMap). Use DialStream for
// that; Wrap runs one stream on a dedicated connection.
package grpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/onlymaj/v2ray-client-go/internal/transport"
)

func init() { transport.Register("grpc", New) }

// Settings is the JSON settings blob of the "grpc" layer.
//
//	{"serviceName":"", "multiMode":false, "authority":"", "userAgent":"",
//	 "idleTimeout":60, "healthCheckTimeout":20}
//
// serviceName is either a plain name (path "/<name>/Tun") or, when it
// starts with "/", a custom path whose last element is the stream name,
// e.g. "/my/path/Tun" (Xray grpc/config.go getServiceName etc.).
// idleTimeout / healthCheckTimeout (seconds) mirror grpc keepalive
// Time / Timeout: a PING is sent after idleTimeout without frames and the
// connection is dropped if no reply arrives within healthCheckTimeout.
// 0 selects the defaults shown above; a negative value disables pings.
// authority defaults to the remote address; the caller should set it to
// the TLS server name or domain (Xray: authority > serverName > domain).
type Settings struct {
	ServiceName        string `json:"serviceName"`
	MultiMode          bool   `json:"multiMode"`
	Authority          string `json:"authority"`
	UserAgent          string `json:"userAgent"`
	IdleTimeout        int    `json:"idleTimeout"`
	HealthCheckTimeout int    `json:"healthCheckTimeout"`
}

// StreamDialer opens tunnels as streams over a shared HTTP/2 connection.
// dialRaw must return a connection ready to speak HTTP/2 (TLS with ALPN
// "h2" negotiated, or cleartext with prior knowledge); it is called only
// when no usable connection exists (none yet, dead, or out of streams).
type StreamDialer interface {
	DialStream(ctx context.Context, dialRaw func(ctx context.Context) (net.Conn, error)) (net.Conn, error)
}

// Client implements transport.Layer and StreamDialer.
type Client struct {
	path      string
	authority string
	ua        string
	t         http2.Transport

	mu  sync.Mutex
	cc  *http2.ClientConn
	raw net.Conn // underlying conn of cc, for addresses
}

var _ StreamDialer = (*Client)(nil)

// New is the transport.Factory for "grpc".
func New(settings []byte) (transport.Layer, error) {
	var s Settings
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &s); err != nil {
			return nil, fmt.Errorf("grpc: settings: %w", err)
		}
	}
	stream := tunStreamName(s.ServiceName)
	if s.MultiMode {
		stream = tunMultiStreamName(s.ServiceName)
	}
	c := &Client{
		path:      "/" + serviceName(s.ServiceName) + "/" + stream,
		authority: s.Authority,
		ua:        s.UserAgent,
	}
	if c.ua == "" {
		c.ua = "grpc-go/1.73.0"
	}
	idle, hc := s.IdleTimeout, s.HealthCheckTimeout
	if idle == 0 {
		idle = 60
	}
	if hc == 0 {
		hc = 20
	}
	if idle > 0 {
		c.t.ReadIdleTimeout = time.Duration(idle) * time.Second
		if hc > 0 {
			c.t.PingTimeout = time.Duration(hc) * time.Second
		}
	}
	return c, nil
}

// serviceName mirrors Xray grpc/config.go getServiceName.
func serviceName(s string) string {
	if !strings.HasPrefix(s, "/") {
		return url.PathEscape(s)
	}
	last := strings.LastIndex(s, "/")
	if last < 1 {
		last = 1
	}
	parts := strings.Split(s[1:last], "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// tunStreamName mirrors Xray grpc/config.go getTunStreamName.
func tunStreamName(s string) string {
	if !strings.HasPrefix(s, "/") {
		return "Tun"
	}
	end := s[strings.LastIndex(s, "/")+1:]
	return url.PathEscape(strings.Split(end, "|")[0])
}

// tunMultiStreamName mirrors Xray grpc/config.go getTunMultiStreamName
// (client side: the last path element is the multi stream name).
func tunMultiStreamName(s string) string {
	if !strings.HasPrefix(s, "/") {
		return "TunMulti"
	}
	end := s[strings.LastIndex(s, "/")+1:]
	names := strings.Split(end, "|")
	return url.PathEscape(names[len(names)-1])
}

// Wrap runs a single tunnel on its own HTTP/2 connection over conn.
// Closing the returned conn closes conn.
func (c *Client) Wrap(ctx context.Context, conn net.Conn) (net.Conn, error) {
	cc, err := c.t.NewClientConn(conn)
	if err != nil {
		return nil, fmt.Errorf("grpc: %w", err)
	}
	s := c.open(cc, conn)
	s.onClose = func() { cc.Close() }
	return s, nil
}

// DialStream opens a tunnel on the shared HTTP/2 connection, dialing a new
// one through dialRaw when needed.
func (c *Client) DialStream(ctx context.Context, dialRaw func(ctx context.Context) (net.Conn, error)) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// ReserveNewRequest atomically checks liveness / stream limits and
	// claims a slot that the next RoundTrip uses.
	if c.cc == nil || !c.cc.ReserveNewRequest() {
		if old := c.cc; old != nil {
			// Let its remaining streams finish, then close it.
			go old.Shutdown(context.Background())
			c.cc = nil
		}
		raw, err := dialRaw(ctx)
		if err != nil {
			return nil, err
		}
		cc, err := c.t.NewClientConn(raw)
		if err != nil {
			raw.Close()
			return nil, fmt.Errorf("grpc: %w", err)
		}
		if !cc.ReserveNewRequest() {
			cc.Close()
			return nil, errors.New("grpc: new connection refuses streams")
		}
		c.cc, c.raw = cc, raw
	}
	return c.open(c.cc, c.raw), nil
}

// Close closes the shared HTTP/2 connection (aborting its streams) so a
// discarded Client stops sending keepalive pings. A later DialStream dials
// again.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc == nil {
		return nil
	}
	err := c.cc.Close()
	c.cc, c.raw = nil, nil
	return err
}

// open starts the streaming call. RoundTrip runs in the background because
// the server may send response headers only after the client's first
// message (grpc-go sends headers lazily).
func (c *Client) open(cc *http2.ClientConn, raw net.Conn) *streamConn {
	authority := c.authority
	if authority == "" {
		authority = raw.RemoteAddr().String()
	}
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+authority+c.path, pr)
	req.Host = authority
	req.Header = http.Header{
		"Content-Type": {"application/grpc"},
		"Te":           {"trailers"},
		"User-Agent":   {c.ua},
	}
	s := &streamConn{
		raw: raw, cancel: cancel,
		done: make(chan struct{}),
		rch:  make(chan [][]byte), wch: make(chan []byte),
		rdl: newDeadline(), wdl: newDeadline(),
	}
	go s.writeLoop(pw)
	go s.readLoop(cc, req, pr)
	return s
}

// readLoop performs the call and feeds decoded messages to Read. Reading
// here rather than in Read lets a read deadline interrupt Read without
// breaking the stream.
func (s *streamConn) readLoop(cc *http2.ClientConn, req *http.Request, pr *io.PipeReader) {
	defer close(s.rch)
	resp, err := cc.RoundTrip(req)
	if err == nil {
		defer resp.Body.Close()
		err = checkResponse(resp)
	}
	if err != nil {
		pr.CloseWithError(err) // fail pending Writes
		s.rerr = err
		return
	}
	for {
		msg, err := readMessage(resp.Body)
		if err == io.EOF {
			if serr := statusErr(resp.Trailer); serr != nil {
				err = serr
			}
		}
		var entries [][]byte
		if err == nil {
			entries, err = decodeHunks(msg)
		}
		if err != nil {
			s.rerr = err
			return
		}
		if len(entries) == 0 {
			continue
		}
		select {
		case s.rch <- entries:
		case <-s.done:
			s.rerr = net.ErrClosed
			return
		}
	}
}

// writeLoop sends messages handed over by Write; nil means CloseWrite.
// The unbuffered wch gives Write backpressure of one message.
func (s *streamConn) writeLoop(pw *io.PipeWriter) {
	defer pw.Close()
	for {
		select {
		case msg := <-s.wch:
			if msg == nil {
				return
			}
			if _, err := pw.Write(msg); err != nil {
				s.werr.CompareAndSwap(nil, &err)
				return
			}
		case <-s.done:
			return
		}
	}
}

func checkResponse(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("grpc: HTTP status %s", resp.Status)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/grpc") {
		return fmt.Errorf("grpc: content-type %q", resp.Header.Get("Content-Type"))
	}
	// Trailers-Only response: grpc-status arrives in the headers.
	return statusErr(resp.Header)
}

func statusErr(h http.Header) error {
	if st := h.Get("Grpc-Status"); st != "" && st != "0" {
		return fmt.Errorf("grpc: status %s: %s", st, h.Get("Grpc-Message"))
	}
	return nil
}

// maxMessage bounds a received message (grpc-go's default receive limit).
const maxMessage = 4 << 20

// maxChunk bounds the payload of one sent message.
const maxChunk = 32 << 10

// streamConn is one tunnel. Deadlines follow net.Conn semantics: an
// expired deadline fails blocked and future calls with
// os.ErrDeadlineExceeded, and extending it makes the conn usable again.
type streamConn struct {
	raw     net.Conn
	cancel  context.CancelFunc
	onClose func()
	done    chan struct{} // closed by Close
	once    sync.Once

	rch     chan [][]byte // from readLoop; closed on end of stream
	rerr    error         // set by readLoop before closing rch
	pending [][]byte      // received entries not yet returned by Read

	wch      chan []byte // to writeLoop
	werr     atomic.Pointer[error]
	wclosed  bool // CloseWrite done; guarded by wmu
	wmu      sync.Mutex
	rdl, wdl *deadline
}

func (s *streamConn) Read(p []byte) (int, error) {
	if len(s.pending) == 0 {
		select {
		case <-s.rdl.wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		select {
		case e, ok := <-s.rch:
			if !ok {
				return 0, s.rerr
			}
			s.pending = e
		case <-s.rdl.wait():
			return 0, os.ErrDeadlineExceeded
		case <-s.done:
			return 0, net.ErrClosed
		}
	}
	n := copy(p, s.pending[0])
	if s.pending[0] = s.pending[0][n:]; len(s.pending[0]) == 0 {
		s.pending = s.pending[1:]
	}
	return n, nil
}

func (s *streamConn) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	n := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), maxChunk)]
		if err := s.send(encodeHunk(chunk)); err != nil {
			return n, err
		}
		n += len(chunk)
		p = p[len(chunk):]
	}
	return n, nil
}

// send hands msg to writeLoop; s.wmu must be held.
func (s *streamConn) send(msg []byte) error {
	if s.wclosed {
		return net.ErrClosed
	}
	if err := s.werr.Load(); err != nil {
		return *err
	}
	select {
	case <-s.wdl.wait():
		return os.ErrDeadlineExceeded
	default:
	}
	select {
	case s.wch <- msg:
		return nil
	case <-s.wdl.wait():
		return os.ErrDeadlineExceeded
	case <-s.done:
		return net.ErrClosed
	}
}

// CloseWrite half-closes the tunnel (END_STREAM) after already written
// data, like grpc CloseSend.
func (s *streamConn) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	err := s.send(nil)
	s.wclosed = true
	return err
}

// Close aborts the stream (Xray HunkReaderWriter.Close cancels the call).
func (s *streamConn) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.cancel()
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

func (s *streamConn) LocalAddr() net.Addr  { return s.raw.LocalAddr() }
func (s *streamConn) RemoteAddr() net.Addr { return s.raw.RemoteAddr() }

func (s *streamConn) SetDeadline(t time.Time) error {
	s.rdl.set(t)
	s.wdl.set(t)
	return nil
}
func (s *streamConn) SetReadDeadline(t time.Time) error  { s.rdl.set(t); return nil }
func (s *streamConn) SetWriteDeadline(t time.Time) error { s.wdl.set(t); return nil }

// deadline is a channel closed when the deadline passes; a copy of
// pipeDeadline in Go's net/pipe.go.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func newDeadline() *deadline { return &deadline{cancel: make(chan struct{})} }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // wait for the timer callback to close cancel
	}
	d.timer = nil
	closed := false
	select {
	case <-d.cancel:
		closed = true
	default:
	}
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		c := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(c) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

// encodeHunk returns a gRPC Length-Prefixed-Message carrying a Hunk
// (equivalently a one-entry MultiHunk) with data p.
func encodeHunk(p []byte) []byte {
	b := make([]byte, 5, 5+1+binary.MaxVarintLen64+len(p))
	b = append(b, 0x0A) // field 1, wire type 2 (length-delimited)
	b = binary.AppendUvarint(b, uint64(len(p)))
	b = append(b, p...)
	// b[0] = 0: not compressed.
	binary.BigEndian.PutUint32(b[1:5], uint32(len(b)-5))
	return b
}

// readMessage reads one gRPC Length-Prefixed-Message and returns its body.
func readMessage(r io.Reader) ([]byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, errors.New("grpc: truncated message header")
		}
		return nil, err
	}
	if h[0] != 0 {
		return nil, errors.New("grpc: compressed messages not supported")
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > maxMessage {
		return nil, fmt.Errorf("grpc: message too large (%d)", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, fmt.Errorf("grpc: truncated message: %w", err)
	}
	return msg, nil
}

// decodeHunks returns the non-empty field-1 entries of a Hunk or MultiHunk
// in order, skipping unknown fields (protobuf wire format).
func decodeHunks(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("grpc: bad protobuf tag")
		}
		b = b[n:]
		switch tag & 7 {
		case 0: // varint
			if _, n = binary.Uvarint(b); n <= 0 {
				return nil, errors.New("grpc: bad protobuf varint")
			}
			b = b[n:]
		case 1: // 64-bit
			if len(b) < 8 {
				return nil, errors.New("grpc: truncated protobuf")
			}
			b = b[8:]
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, errors.New("grpc: truncated protobuf")
			}
			v := b[n : n+int(l)]
			b = b[n+int(l):]
			if tag>>3 == 1 && len(v) > 0 {
				out = append(out, v)
			}
		case 5: // 32-bit
			if len(b) < 4 {
				return nil, errors.New("grpc: truncated protobuf")
			}
			b = b[4:]
		default:
			return nil, fmt.Errorf("grpc: unsupported protobuf wire type %d", tag&7)
		}
	}
	return out, nil
}
