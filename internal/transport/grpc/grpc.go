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
	"bufio"
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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
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

// streamWindow is the HTTP/2 receive window of one tunnel: the most a
// stream buffers when its reader stalls. Throughput per stream is about
// streamWindow per round trip (10 Mbit/s at 200 ms).
const streamWindow = 256 << 10

// maxHeaderList bounds the response headers and trailers of one stream.
const maxHeaderList = 16 << 10

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
	t         *http2.Transport

	mu      sync.Mutex
	cc      *http2.ClientConn
	raw     net.Conn // underlying conn of cc, for addresses
	closed  bool
	streams int            // tunnels open on cc
	srcs    map[string]int // and how many of them each source has
	idle    *time.Timer    // closes cc; running while streams is 0
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
	if s.Authority != "" && !validAuthority(s.Authority) {
		return nil, fmt.Errorf("grpc: invalid authority %q", s.Authority)
	}
	if hasCtl(s.ServiceName) {
		return nil, fmt.Errorf("grpc: invalid serviceName %q", s.ServiceName)
	}
	if !httpguts.ValidHeaderFieldValue(s.UserAgent) {
		return nil, fmt.Errorf("grpc: invalid userAgent %q", s.UserAgent)
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
	// The default receive window is 4 MiB per stream, held in memory while
	// the reader is slow: a LAN device that stops reading its downloads
	// would pin 4 MiB per connection. ConfigureTransports is the only way to
	// set the window; the http.Transport itself is never used.
	t, err := http2.ConfigureTransports(&http.Transport{
		HTTP2: &http.HTTP2Config{MaxReceiveBufferPerStream: streamWindow},
		// Otherwise the transport asks for gzip and inflates a reply that
		// claims it, which gRPC never does (round 19).
		DisableCompression: true,
	})
	if err != nil {
		return nil, fmt.Errorf("grpc: %w", err)
	}
	// The default lets a server send 10 MiB of response headers, kept for
	// the life of the stream. A gRPC response needs a few hundred bytes.
	t.MaxHeaderListSize = maxHeaderList
	// Without this a server that stops reading its socket (but keeps
	// sending, so the read idle check never fires) blocks one writer for
	// ever with the connection's write lock held, and every later stream
	// queues behind it. See guardConn for what happens on the timeout.
	t.WriteByteTimeout = time.Duration(writeTimeout.Load())
	c.t = t
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

// validAuthority reports whether a is a plain host[:port] usable as the
// :authority and as the host of the request URL.
func validAuthority(a string) bool {
	if !httpguts.ValidHostHeader(a) {
		return false
	}
	u, err := url.Parse("https://" + a)
	return err == nil && u.Host == a && u.User == nil
}

// hasCtl reports whether s contains an ASCII control character.
func hasCtl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7F })
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

// writeTimeout is how long a write to the server may make no progress.
// Atomic so tests can lower it.
var writeTimeout atomic.Int64

// idleTimeout is how long the shared connection is kept with no tunnel on
// it (see streamDone). It is the lifetime of a warm pooled connection of
// the other transports, and shorter than the default health check interval:
// a probe is a tunnel too, and must not keep the connection of every
// client of a subscription open from one probe to the next. Atomic so
// tests can lower it.
var idleTimeout atomic.Int64

func init() {
	writeTimeout.Store(int64(30 * time.Second))
	idleTimeout.Store(int64(30 * time.Second))
}

// guardConn sits between the HTTP/2 client and the connection to the server.
//
// Reading, it rewrites SETTINGS_MAX_FRAME_SIZE in the server's SETTINGS
// frames to the minimum, 16384. The HTTP/2 client allocates an upload buffer
// of that size (up to 512 KiB) for every stream and keeps it while the
// request body is open, which for a tunnel is its whole life: a server
// advertising 1 MiB, as Go's own HTTP/2 server does, would cost 512 KiB per
// tunnel. A sender may always use smaller frames than the peer allows.
//
// Writing, it closes the connection on any error. The HTTP/2 client only
// remembers a write error; it would go on handing out streams on a
// connection that can no longer send.
type guardConn struct {
	net.Conn
	// Frame scanner state; only the HTTP/2 read loop calls Read.
	hdr      [9]byte
	nh       int    // header bytes collected
	left     int    // payload bytes left in the current frame
	settings bool   // the current frame is SETTINGS (not an ACK)
	off      int    // offset in the SETTINGS payload
	id       uint16 // identifier of the setting at off
}

func (g *guardConn) Read(p []byte) (int, error) {
	n, err := g.Conn.Read(p)
	g.scan(p[:n])
	return n, err
}

// scan follows the frame boundaries in b (RFC 9113 section 4.1) and patches
// SETTINGS payloads (section 6.5.1: 2-byte identifier, 4-byte value).
func (g *guardConn) scan(b []byte) {
	for len(b) > 0 {
		if g.nh < len(g.hdr) {
			k := copy(g.hdr[g.nh:], b)
			g.nh, b = g.nh+k, b[k:]
			if g.nh < len(g.hdr) {
				return
			}
			g.left = int(g.hdr[0])<<16 | int(g.hdr[1])<<8 | int(g.hdr[2])
			g.settings, g.off = g.hdr[3] == 0x4 && g.hdr[4]&0x1 == 0, 0
			if g.left == 0 {
				g.nh = 0
			}
			continue
		}
		k := min(len(b), g.left)
		if g.settings {
			for i := range k {
				switch pos := g.off % 6; pos {
				case 0:
					g.id = uint16(b[i]) << 8
				case 1:
					g.id |= uint16(b[i])
				default:
					if g.id == 0x5 { // SETTINGS_MAX_FRAME_SIZE := 16384
						b[i] = [4]byte{0, 0, 0x40, 0}[pos-2]
					}
				}
				g.off++
			}
		}
		b, g.left = b[k:], g.left-k
		if g.left == 0 {
			g.nh = 0
		}
	}
}

func (g *guardConn) Write(p []byte) (int, error) {
	n, err := g.Conn.Write(p)
	if err != nil {
		g.Conn.Close()
	}
	return n, err
}

// Wrap runs a single tunnel on its own HTTP/2 connection over conn.
// Closing the returned conn closes conn.
func (c *Client) Wrap(ctx context.Context, conn net.Conn) (net.Conn, error) {
	cc, err := c.t.NewClientConn(&guardConn{Conn: conn})
	if err != nil {
		return nil, fmt.Errorf("grpc: %w", err)
	}
	s, err := c.open(cc, conn, transport.Source(ctx), nil)
	if err != nil {
		cc.Close()
		return nil, err
	}
	s.onClose = func() { cc.Close() }
	return s, nil
}

// DialStream opens a tunnel on the shared HTTP/2 connection, dialing a new
// one through dialRaw when needed.
func (c *Client) DialStream(ctx context.Context, dialRaw func(ctx context.Context) (net.Conn, error)) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	// ReserveNewRequest atomically checks liveness / stream limits and
	// claims a slot that the next RoundTrip uses.
	if c.cc == nil || !c.cc.ReserveNewRequest() {
		if old := c.cc; old != nil {
			// Let its remaining streams finish, then close it. Until then
			// it is counted in drainSet.
			if c.streams > 0 {
				if victim := drainAdd(old, c.srcs); victim != nil {
					go victim.Close()
				}
			}
			go func() {
				// A tunnel that has reserved the last stream but not yet
				// started it would fail: Shutdown closes a connection
				// without streams at once (round 22).
				for i := 0; i < 100 && old.State().StreamsReserved > 0; i++ {
					time.Sleep(10 * time.Millisecond)
				}
				old.Shutdown(context.Background())
				drainDrop(old)
			}()
			idleDrop(c, old)
			c.cc, c.raw = nil, nil
		}
		c.streams, c.srcs = 0, nil
		raw, err := dialRaw(ctx)
		if err != nil {
			return nil, err
		}
		cc, err := c.t.NewClientConn(&guardConn{Conn: raw})
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
	if c.idle != nil {
		c.idle.Stop()
		c.idle = nil
		idleDrop(c, c.cc)
	}
	cc := c.cc
	src := transport.Source(ctx)
	s, err := c.open(cc, c.raw, src, func() { c.streamDone(cc, src) })
	if err != nil {
		c.streamDoneLocked(cc)
		return nil, err
	}
	c.streams++
	if c.srcs == nil {
		c.srcs = map[string]int{}
	}
	c.srcs[src]++
	return s, nil
}

// streamDone is called when a tunnel on cc has ended. When it was the last
// one, cc is closed after idleTimeout unless a new tunnel comes first.
// Without this the connection lived for ever: every health-checked client
// of a subscription (up to 1000) kept a TLS and HTTP/2 connection, and its
// pings, after one probe, and so did a client that was disabled. The timer
// is ours rather than the HTTP/2 transport's IdleConnTimeout, so that it
// cannot close a connection DialStream has just handed a tunnel, and so
// that the closed connection is let go of here.
func (c *Client) streamDone(cc *http2.ClientConn, src string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc == cc {
		c.streams--
		if c.srcs[src]--; c.srcs[src] <= 0 {
			delete(c.srcs, src)
		}
	} else {
		drainDone(cc, src)
	}
	c.streamDoneLocked(cc)
}

func (c *Client) streamDoneLocked(cc *http2.ClientConn) {
	if c.cc != cc || c.streams > 0 || c.idle != nil {
		return
	}
	c.idle = time.AfterFunc(time.Duration(idleTimeout.Load()), func() { c.closeIdle(cc) })
	for _, old := range idleAdd(c, cc) {
		go old.c.closeIdle(old.cc) // not here: c.mu is held
	}
}

// closeIdle closes cc if it is still the client's connection and has no
// tunnel.
func (c *Client) closeIdle(cc *http2.ClientConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc == cc && c.streams == 0 {
		if c.idle != nil {
			c.idle.Stop()
		}
		idleDrop(c, cc)
		cc.Close()
		c.cc, c.raw, c.idle = nil, nil, nil
	}
}

// maxDraining bounds, over all clients, the replaced connections that still
// have tunnels. A server that allows one stream per connection would
// otherwise get a TLS and HTTP/2 connection for every tunnel (round 21).
// Refusing new tunnels at the bound locked out clients whose server retires
// connections with GOAWAY, as nginx does after 1000 requests or an hour; a
// bound per client, closing its oldest, let one LAN device that parks a
// tunnel on each retired connection have other devices' long-lived tunnels
// cut (round 22). So the connection closed is one of the source that has
// tunnels on the most replaced connections, the one with the fewest tunnels
// of other sources, the oldest first. A variable for tests.
var maxDraining = 32

type drained struct {
	cc   *http2.ClientConn
	srcs map[string]int // tunnels per source
}

// drainSet lists the replaced connections, oldest first. Like idleSet's,
// its lock is taken with a Client's mu held, never the other way round.
var drainSet struct {
	sync.Mutex
	list []drained
}

// drainAdd records the replaced cc and its tunnels. Over maxDraining it
// returns the connection to close.
func drainAdd(cc *http2.ClientConn, srcs map[string]int) *http2.ClientConn {
	drainSet.Lock()
	defer drainSet.Unlock()
	drainSet.list = append(drainSet.list, drained{cc, srcs})
	if len(drainSet.list) <= maxDraining {
		return nil
	}
	on := map[string]int{} // replaced connections each source has tunnels on
	most := 0
	for _, d := range drainSet.list {
		for src := range d.srcs {
			on[src]++
			most = max(most, on[src])
		}
	}
	victim, others := 0, -1
	for i, d := range drainSet.list {
		own, all := 0, 0
		for src, n := range d.srcs {
			all += n
			if on[src] == most {
				own += n
			}
		}
		if own > 0 && (others < 0 || all-own < others) {
			victim, others = i, all-own
		}
	}
	cc = drainSet.list[victim].cc
	drainSet.list = slices.Delete(drainSet.list, victim, victim+1)
	return cc
}

// drainDone notes that a tunnel of src on the replaced cc has ended.
func drainDone(cc *http2.ClientConn, src string) {
	drainSet.Lock()
	defer drainSet.Unlock()
	for _, d := range drainSet.list {
		if d.cc == cc {
			if d.srcs[src]--; d.srcs[src] <= 0 {
				delete(d.srcs, src)
			}
			return
		}
	}
}

func drainDrop(cc *http2.ClientConn) {
	drainSet.Lock()
	defer drainSet.Unlock()
	drainSet.list = slices.DeleteFunc(drainSet.list, func(d drained) bool { return d.cc == cc })
}

// maxIdleConns bounds the connections without a tunnel over all clients.
// One lingers for idleTimeout after every health probe, and a subscription
// of 1000 gRPC servers probed in turn had hundreds open at once, 64 MiB
// and more with no traffic at all (round 21). A variable for tests.
var maxIdleConns = 8

type idleConn struct {
	c  *Client
	cc *http2.ClientConn
}

// idleSet lists the connections without a tunnel, oldest first. Its lock
// is taken with a Client's mu held, never the other way round.
var idleSet struct {
	sync.Mutex
	list []idleConn
}

// idleAdd records cc as idle and returns the oldest ones beyond
// maxIdleConns; the caller closes them.
func idleAdd(c *Client, cc *http2.ClientConn) []idleConn {
	idleSet.Lock()
	defer idleSet.Unlock()
	idleSet.list = append(idleSet.list, idleConn{c, cc})
	n := len(idleSet.list) - maxIdleConns
	if n <= 0 {
		return nil
	}
	old := slices.Clone(idleSet.list[:n])
	idleSet.list = append(idleSet.list[:0], idleSet.list[n:]...)
	return old
}

func idleDrop(c *Client, cc *http2.ClientConn) {
	idleSet.Lock()
	defer idleSet.Unlock()
	for i, e := range idleSet.list {
		if e.c == c && e.cc == cc {
			idleSet.list = append(idleSet.list[:i], idleSet.list[i+1:]...)
			return
		}
	}
}

// Close closes the shared HTTP/2 connection (aborting its streams) so a
// discarded Client stops sending keepalive pings. A later DialStream fails:
// a connection still holding the old client must not open a new shared
// connection that nothing would close.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.idle != nil {
		c.idle.Stop()
		c.idle = nil
	}
	if c.cc == nil {
		return nil
	}
	idleDrop(c, c.cc)
	err := c.cc.Close()
	c.cc, c.raw, c.srcs = nil, nil, nil
	return err
}

// open starts the streaming call. RoundTrip runs in the background because
// the server may send response headers only after the client's first
// message (grpc-go sends headers lazily).
func (c *Client) open(cc *http2.ClientConn, raw net.Conn, src string, ended func()) (*streamConn, error) {
	authority := c.authority
	if authority == "" {
		authority = raw.RemoteAddr().String()
	}
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+authority+c.path, pr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("grpc: %w", err)
	}
	req.Host = authority
	req.Header = http.Header{
		"Content-Type": {"application/grpc"},
		"Te":           {"trailers"},
		"User-Agent":   {c.ua},
	}
	s := &streamConn{
		raw: raw, cancel: cancel, src: src,
		done: make(chan struct{}), cut: make(chan struct{}), wend: make(chan struct{}),
		rch: make(chan []byte), wch: make(chan []byte),
		rdl: newDeadline(), wdl: newDeadline(),
	}
	go s.writeLoop(pw)
	go s.readLoop(cc, req, pr, ended)
	return s, nil
}

// readLoop performs the call and feeds decoded messages to Read. Reading
// here rather than in Read lets a read deadline interrupt Read without
// breaking the stream.
// ended, if not nil, is called when the call is over.
func (s *streamConn) readLoop(cc *http2.ClientConn, req *http.Request, pr *io.PipeReader, ended func()) {
	if ended != nil {
		defer ended()
	}
	defer close(s.rch)
	resp, err := cc.RoundTrip(req)
	if err == nil {
		defer resp.Body.Close()
		err = checkResponse(resp)
		// Not needed again, and kept for the life of the tunnel otherwise:
		// a server can send hundreds of empty headers under the size limit.
		resp.Header = nil
	}
	if err != nil {
		pr.CloseWithError(err) // fail pending Writes
		s.rerr = err
		return
	}
	var b backlog
	defer func() {
		s.setSlow(false)
		if b.timer != nil {
			b.timer.Stop()
		}
		select {
		case <-s.cut: // whatever error the cut surfaced as, say why
			s.rerr = errStalled
		default:
		}
	}()
	br := bufio.NewReaderSize(resp.Body, 4<<10)
	emit := func(data []byte) error { return s.deliver(data, &b) }
	for {
		err := readHunks(br, emit)
		if err == io.EOF {
			if serr := statusErr(resp.Trailer); serr != nil {
				err = serr
			}
		}
		if err != nil {
			s.rerr = err
			return
		}
	}
}

// Slow readers. HTTP/2 keeps up to streamWindow buffered for a stream whose
// reader is behind, on top of the message in hand. The cap on open conns
// allows 256 such streams, 64 MiB against a 32 MiB heap limit, from LAN
// devices that start downloads and then read slowly or not at all. The
// relay's idle timer does not help: a trickle in either direction resets it.
//
// A stream is slow when, over a slowWindow, data was waiting for the reader
// at least half the time and the reader took less than slowFloor bytes per
// second. Windows follow one another for as long as data arrives; a reader
// that catches up now and then is still judged on the whole window, so
// stalling and then taking a few pieces in a burst does not escape.
//
// At most maxSlow streams may be slow at once (about 9 MiB: a window plus a
// readStep piece or two each). When one more turns slow, a stream is ended:
// the one slow for the longest among those of the source (LAN device, see
// transport.WithSource) that has the most slow streams. A device holding
// many slow streams loses its own, and cannot have another device's paused
// download cut. Readers above the floor are not limited; what they can pin
// is bounded by the bandwidth they really use (about one second of it).
const slowFloor = streamWindow // bytes per second

// Atomics so tests can lower them.
var (
	slowWindow atomic.Int64 // a time.Duration
	maxSlow    atomic.Int32

	slowMu   sync.Mutex
	slowList []*streamConn // oldest first
)

func init() {
	slowWindow.Store(int64(2 * time.Second))
	maxSlow.Store(32)
}

var errStalled = errors.New("grpc: stream ended: its reader is too slow and too many streams are waiting for their readers")

// backlog is readLoop's record of how its reader keeps up.
type backlog struct {
	start  time.Time     // start of the current window; zero before the first data
	waited time.Duration // time in the window with data waiting for the reader
	taken  int           // bytes the reader took in the window
	timer  *time.Timer
}

// judge closes the window if it is over and starts the next one.
func (b *backlog) judge(s *streamConn, now time.Time) {
	elapsed := now.Sub(b.start)
	if elapsed < time.Duration(slowWindow.Load()) {
		return
	}
	s.setSlow(b.waited*2 >= elapsed && int64(b.taken)*int64(time.Second) < slowFloor*int64(elapsed))
	b.start, b.waited, b.taken = now, 0, 0
}

// deliver hands data to Read and keeps the slow-reader account.
func (s *streamConn) deliver(data []byte, b *backlog) error {
	select {
	case <-s.cut:
		return errStalled
	default:
	}
	now := time.Now()
	s.last.Store(now.UnixNano())
	if b.start.IsZero() {
		b.start = now
	}
	b.judge(s, now)
	select {
	case s.rch <- data: // the reader was waiting
		b.taken += len(data)
		return nil
	case <-s.done:
		return net.ErrClosed
	default:
	}
	s.blocked.Store(true)
	defer s.blocked.Store(false)
	for {
		left := max(time.Duration(slowWindow.Load())-now.Sub(b.start), time.Millisecond)
		if b.timer == nil {
			b.timer = time.NewTimer(left)
		} else {
			b.timer.Reset(left)
		}
		select {
		case s.rch <- data:
			b.timer.Stop()
			t := time.Now()
			s.last.Store(t.UnixNano())
			b.waited += t.Sub(now)
			b.taken += len(data)
			return nil
		case <-s.done:
			b.timer.Stop()
			return net.ErrClosed
		case <-s.cut:
			b.timer.Stop()
			return errStalled
		case <-b.timer.C:
			t := time.Now()
			b.waited += t.Sub(now)
			now = t
			b.judge(s, now)
		}
	}
}

// setSlow adds s to or removes it from the slow streams. Adding one over
// maxSlow ends a stream (see "Slow readers" above).
func (s *streamConn) setSlow(slow bool) {
	slowMu.Lock()
	if slow == s.slow || s.ended {
		slowMu.Unlock()
		return
	}
	s.slow = slow
	var victim *streamConn
	if slow {
		slowList = append(slowList, s)
		if len(slowList) > int(maxSlow.Load()) {
			// A stream that has been waiting for the server, not for its
			// reader, for a whole window has nothing buffered: it was slow
			// and is now idle. It is judged again when data arrives.
			idle := time.Now().UnixNano() - slowWindow.Load()
			slowList = slices.DeleteFunc(slowList, func(o *streamConn) bool {
				if o == s || o.blocked.Load() || o.last.Load() > idle {
					return false
				}
				o.slow = false
				return true
			})
		}
		if len(slowList) > int(maxSlow.Load()) {
			count, most := map[string]int{}, 0
			for _, o := range slowList {
				count[o.src]++
				most = max(most, count[o.src])
			}
			// Of that source, the oldest whose reader has data waiting
			// right now; one that has just resumed is still listed until
			// its window ends, but pins nothing.
			i := slices.IndexFunc(slowList, func(o *streamConn) bool { return count[o.src] == most && o.blocked.Load() })
			if i < 0 {
				i = slices.IndexFunc(slowList, func(o *streamConn) bool { return count[o.src] == most })
			}
			victim = slowList[i]
			victim.slow, victim.ended = false, true
			slowList = slices.Delete(slowList, i, i+1)
		}
	} else if i := slices.Index(slowList, s); i >= 0 {
		slowList = slices.Delete(slowList, i, i+1)
	}
	slowMu.Unlock()
	if victim != nil {
		close(victim.cut) // once: a stream leaves the list when it is cut
		victim.cancel()   // wakes a readLoop blocked on the response body
	}
}

// writeLoop sends messages handed over by Write; nil means CloseWrite.
// The unbuffered wch gives Write backpressure of one message.
func (s *streamConn) writeLoop(pw *io.PipeWriter) {
	defer pw.Close()
	defer close(s.wend)
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

// maxMessage bounds the declared length of a received message. Xray sends
// one buffer (at most 8 KiB) per Tun message and one MultiBuffer per TunMulti
// message, so 1 MiB leaves plenty of room. A message is never held whole
// (see readHunks), so this is not what a stream costs.
const maxMessage = 1 << 20

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

	cut  chan struct{} // closed when the stream is ended as a slow reader
	slow bool          // in slowList; guarded by slowMu
	src  string        // whose stream this is, for the slow-reader cap
	// For setSlow, about another stream: readLoop is in deliver waiting
	// for the reader, and when (unix nanoseconds) deliver last ran.
	blocked atomic.Bool
	last    atomic.Int64
	ended   bool // cut closed; guarded by slowMu

	rch     chan []byte // from readLoop; closed on end of stream
	rerr    error       // set by readLoop before closing rch
	pending []byte      // received data not yet returned by Read

	wch      chan []byte   // to writeLoop
	wend     chan struct{} // closed when writeLoop returns
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
	n := copy(p, s.pending)
	if s.pending = s.pending[n:]; len(s.pending) == 0 {
		s.pending = nil // release the message buffer
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
	case <-s.wend: // writeLoop is gone: nothing would ever take msg
		if err := s.werr.Load(); err != nil {
			return *err
		}
		return io.ErrClosedPipe
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

// readHunks reads one gRPC Length-Prefixed-Message from r and passes the
// field-1 payloads of its Hunk or MultiHunk to emit, in order, skipping
// unknown fields (protobuf wire format). The message is decoded as it
// arrives and never held whole: a server could otherwise make every stream
// keep a maxMessage buffer, and a second one waiting for the reader. Small
// entries are joined into pieces of up to readStep bytes, so a message of
// 1-byte entries does not become one Read (and one packet) per byte. emit
// owns the slice it is given. io.EOF means the stream ended cleanly before
// a message.
func readHunks(r *bufio.Reader, emit func([]byte) error) error {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return errors.New("grpc: truncated message header")
		}
		return err
	}
	if h[0] != 0 {
		return errors.New("grpc: compressed messages not supported")
	}
	left := int(binary.BigEndian.Uint32(h[1:])) // of the message
	if left > maxMessage {
		return fmt.Errorf("grpc: message too large (%d)", left)
	}
	trunc := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("grpc: truncated message: %w", err)
	}
	uvarint := func() (uint64, error) {
		var v uint64
		for shift := uint(0); shift < 64; shift += 7 {
			if left == 0 {
				return 0, errors.New("grpc: truncated protobuf")
			}
			c, err := r.ReadByte()
			if err != nil {
				return 0, trunc(err)
			}
			left--
			v |= uint64(c&0x7f) << shift
			if c < 0x80 {
				return v, nil
			}
		}
		return 0, errors.New("grpc: bad protobuf varint")
	}
	skip := func(n int) error {
		if n > left {
			return errors.New("grpc: truncated protobuf")
		}
		left -= n
		if _, err := r.Discard(n); err != nil {
			return trunc(err)
		}
		return nil
	}
	var piece []byte
	for left > 0 {
		tag, err := uvarint()
		if err != nil {
			return err
		}
		switch tag & 7 {
		case 0: // varint
			_, err = uvarint()
		case 1: // 64-bit
			err = skip(8)
		case 5: // 32-bit
			err = skip(4)
		case 2: // length-delimited
			var l uint64
			if l, err = uvarint(); err != nil {
				break
			}
			if l > uint64(left) {
				return errors.New("grpc: truncated protobuf")
			}
			if tag>>3 != 1 {
				err = skip(int(l))
				break
			}
			for n := int(l); n > 0; {
				if piece == nil {
					// Never more than what the message can still hold, and
					// little before the bytes are here: a header that only
					// declares a large entry must not make us allocate it.
					piece = make([]byte, 0, min(left, readStart))
				} else if len(piece) == cap(piece) {
					// Exactly: append would round up to a size class.
					np := make([]byte, len(piece), len(piece)+min(left, readStep-len(piece), len(piece)))
					copy(np, piece)
					piece = np
				}
				k := min(n, cap(piece)-len(piece))
				if _, err := io.ReadFull(r, piece[len(piece):len(piece)+k]); err != nil {
					return trunc(err)
				}
				piece = piece[:len(piece)+k]
				n, left = n-k, left-k
				if len(piece) >= min(readStep, len(piece)+left) {
					if err := emit(piece); err != nil {
						return err
					}
					piece = nil
				}
			}
		default:
			return fmt.Errorf("grpc: unsupported protobuf wire type %d", tag&7)
		}
		if err != nil {
			return err
		}
	}
	if len(piece) > 0 {
		return emit(piece)
	}
	return nil
}

// readStep is the largest piece of a message handed to the reader. A piece
// starts at readStart and doubles as its bytes arrive.
const (
	readStep  = 32 << 10
	readStart = 4 << 10
)
