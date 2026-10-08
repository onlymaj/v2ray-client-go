// Package dns is a small DNS forwarder. It answers queries on UDP and TCP
// and resolves each one with DNS-over-TCP to a single upstream, through a
// connection obtained from a DialFunc. The caller's dispatcher routes that
// connection by the querying device's address and the query name, so a
// query takes the same proxy client (or direct / block) as traffic to the
// name itself would.
//
// Responses are cached (LRU, 1024 entries) for the smallest record TTL,
// clamped to [5s, 1h]; negative answers for the SOA minimum, capped at 5
// minutes. Cached answers get the client's ID and decremented TTLs.
// UDP responses larger than the client's limit (512 or its EDNS0 size) are
// truncated to header + question with TC set, so the client retries on TCP.
// At most MaxInFlight upstream queries run at once; a query that gets no
// upstream answer within Timeout is answered SERVFAIL.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// DialFunc opens a TCP connection to dst (the upstream resolver) routed as
// a connection from src to qname would be.
type DialFunc func(ctx context.Context, src netip.Addr, qname string, dst outbound.Addr) (net.Conn, error)

type Options struct {
	Dial     DialFunc
	Upstream string // ip:port or host:port; port defaults to 53

	// RouteKey, if set, returns a key identifying the route Dial would
	// take for (src, qname). One idle upstream connection per key is kept
	// for up to IdleTimeout and reused for later queries with the same key.
	// Without it every query uses a fresh connection.
	RouteKey func(src netip.Addr, qname string) string

	MaxInFlight int           // concurrent upstream queries; default 64
	Timeout     time.Duration // per-query upstream timeout; default 5s
	IdleTimeout time.Duration // pooled connection lifetime; default 10s
	CacheSize   int           // entries; default 1024
	Logf        func(format string, args ...any)
}

type Server struct {
	opts  Options
	cache *cache
	sem   chan struct{}

	mu       sync.Mutex
	upstream outbound.Addr
	upErr    error
	idle     map[string]idleConn
}

type idleConn struct {
	conn  net.Conn
	since time.Time
}

func New(opts Options) *Server {
	if opts.MaxInFlight <= 0 {
		opts.MaxInFlight = 64
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 10 * time.Second
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = 1024
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	s := &Server{
		opts:  opts,
		cache: newCache(opts.CacheSize),
		sem:   make(chan struct{}, opts.MaxInFlight),
		idle:  map[string]idleConn{},
	}
	s.SetUpstream(opts.Upstream)
	return s
}

// SetUpstream changes the upstream resolver and drops pooled connections.
// The cache is kept; call Flush to drop it as well.
func (s *Server) SetUpstream(addr string) {
	a, err := parseUpstream(addr)
	s.mu.Lock()
	s.upstream, s.upErr = a, err
	s.mu.Unlock()
	s.closeIdle()
	if err != nil {
		s.opts.Logf("dns: upstream %q: %v", addr, err)
	}
}

func (s *Server) closeIdle() {
	s.mu.Lock()
	old := s.idle
	s.idle = map[string]idleConn{}
	s.mu.Unlock()
	for _, ic := range old {
		ic.conn.Close()
	}
}

func parseUpstream(addr string) (outbound.Addr, error) {
	if addr == "" {
		return outbound.Addr{}, errors.New("no upstream configured")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = strings.Trim(addr, "[]"), "53"
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return outbound.Addr{}, fmt.Errorf("bad port %q", port)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return outbound.Addr{IP: ip.Unmap(), Port: uint16(p)}, nil
	}
	if host == "" {
		return outbound.Addr{}, errors.New("empty host")
	}
	return outbound.Addr{Domain: host, Port: uint16(p)}, nil
}

// Flush empties the response cache.
func (s *Server) Flush() { s.cache.flush() }

// ListenAndServe serves DNS on addr over both UDP and TCP until ctx is
// cancelled. It returns once both listeners are closed; the error is the
// first listen or serve error, or nil after cancellation.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return err
	}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		pc.Close()
		return err
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		pc.Close()
		ln.Close()
	})
	defer stop()

	errc := make(chan error, 2)
	go func() { errc <- s.serveUDP(ctx, pc) }()
	go func() { errc <- s.serveTCP(ctx, ln) }()
	go s.reapIdle(ctx)

	first := <-errc
	cancel()
	<-errc
	s.closeIdle()
	if parent.Err() != nil {
		return nil
	}
	return first
}

func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn) error {
	// Bounds goroutines for cache hits and queued queries alike.
	handlers := make(chan struct{}, 4*s.opts.MaxInFlight)
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return net.ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if n < headerLen {
			continue
		}
		select {
		case handlers <- struct{}{}:
		default:
			continue // overloaded: drop, the client will retry
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			defer func() { <-handlers }()
			resp := s.handle(ctx, srcOf(from), query)
			if resp == nil {
				return
			}
			pc.WriteTo(truncate(resp, udpLimit(query)), from)
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	conns := make(chan struct{}, 4*s.opts.MaxInFlight)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return net.ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case conns <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-conns }()
			s.serveTCPConn(ctx, c)
		}()
	}
}

// serveTCPConn answers queries on one client connection in order.
func (s *Server) serveTCPConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	src := srcOf(c.RemoteAddr())
	for {
		c.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
		query, err := readMsg(c)
		if err != nil {
			return
		}
		if len(query) < headerLen {
			return
		}
		resp := s.handle(ctx, src, query)
		if resp == nil {
			return
		}
		c.SetWriteDeadline(time.Now().Add(s.opts.Timeout))
		if err := writeMsg(c, resp); err != nil {
			return
		}
	}
}

func srcOf(a net.Addr) netip.Addr {
	switch a := a.(type) {
	case *net.UDPAddr:
		return a.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return a.AddrPort().Addr().Unmap()
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// handle answers one query. It returns nil only for input it cannot even
// reply to.
func (s *Server) handle(ctx context.Context, src netip.Addr, query []byte) []byte {
	h, q, err := parseQuestion(query)
	if err != nil {
		return errorResponse(query, rcodeFormErr)
	}
	if h.Flags&flagQR != 0 {
		return nil // a response, not a query
	}
	if resp := s.cache.get(query, q); resp != nil {
		return resp
	}
	resp, err := s.Exchange(ctx, src, query)
	if err != nil {
		s.opts.Logf("dns: %s %s from %s: %v", q.Name, typeString(q.Type), src, err)
		return errorResponse(query, rcodeServFail)
	}
	s.cache.put(q, resp)
	return resp
}

// Exchange sends query upstream (bypassing the cache) and returns the raw
// response. It waits at most Timeout, including the wait for a free slot.
func (s *Server) Exchange(ctx context.Context, src netip.Addr, query []byte) ([]byte, error) {
	_, q, err := parseQuestion(query)
	if err != nil {
		return nil, err
	}
	qname := strings.ToLower(q.Name)

	ctx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for a free upstream slot: %w", ctx.Err())
	}

	s.mu.Lock()
	up, upErr := s.upstream, s.upErr
	s.mu.Unlock()
	if upErr != nil {
		return nil, upErr
	}
	key := ""
	if s.opts.RouteKey != nil {
		key = s.opts.RouteKey(src, qname) + "|" + up.String()
	}

	// A pooled connection may have been closed by the upstream; retry
	// once on a fresh one.
	if c := s.takeIdle(key); c != nil {
		if resp, err := exchangeOn(ctx, c, query); err == nil {
			s.putIdle(key, c)
			return resp, nil
		}
		c.Close()
	}
	c, err := s.opts.Dial(ctx, src, qname, up)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", up, err)
	}
	resp, err := exchangeOn(ctx, c, query)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("upstream %s: %w", up, err)
	}
	s.putIdle(key, c)
	return resp, nil
}

func exchangeOn(ctx context.Context, c net.Conn, query []byte) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := writeMsg(c, query); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(query)
	for {
		resp, err := readMsg(c)
		if err != nil {
			return nil, err
		}
		if len(resp) >= headerLen && binary.BigEndian.Uint16(resp) == id {
			if !stop() {
				return nil, ctx.Err() // deadline was poisoned; don't reuse c
			}
			c.SetDeadline(time.Time{})
			return resp, nil
		}
		// A stale answer to an earlier, timed-out query: skip it.
	}
}

func (s *Server) takeIdle(key string) net.Conn {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	ic, ok := s.idle[key]
	delete(s.idle, key)
	s.mu.Unlock()
	if !ok {
		return nil
	}
	if time.Since(ic.since) > s.opts.IdleTimeout {
		ic.conn.Close()
		return nil
	}
	return ic.conn
}

func (s *Server) putIdle(key string, c net.Conn) {
	if key == "" {
		c.Close()
		return
	}
	s.mu.Lock()
	old, had := s.idle[key]
	s.idle[key] = idleConn{c, time.Now()}
	s.mu.Unlock()
	if had {
		old.conn.Close()
	}
}

func (s *Server) reapIdle(ctx context.Context) {
	t := time.NewTicker(s.opts.IdleTimeout)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var stale []net.Conn
		s.mu.Lock()
		for k, ic := range s.idle {
			if time.Since(ic.since) > s.opts.IdleTimeout {
				stale = append(stale, ic.conn)
				delete(s.idle, k)
			}
		}
		s.mu.Unlock()
		for _, c := range stale {
			c.Close()
		}
	}
}

func readMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeMsg(w io.Writer, msg []byte) error {
	if len(msg) > 0xffff {
		return errors.New("message too long")
	}
	b := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(b, uint16(len(msg)))
	copy(b[2:], msg)
	_, err := w.Write(b)
	return err
}

func typeString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 65:
		return "HTTPS"
	}
	return "TYPE" + strconv.Itoa(int(t))
}
