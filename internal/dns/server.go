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
//
// With RouteKey set, cached answers are kept per route: an answer fetched
// over one route (say direct, where the ISP may poison it) is never served
// to a device whose queries take another (a proxy, or block).
//
// Each source (IPv4 address or IPv6 /64) may have at most MaxPerSource
// upstream queries and MaxPerSource TCP connections open at once; a query
// over the limit is answered SERVFAIL, a connection over it is closed. TCP
// clients must send each query within TCPIdleTimeout. UDP queries (cache
// hits included) are rate limited per source to RatePerSource per second,
// with bursts of 2.5 times that. Every second query over the rate is
// answered with header + question and TC set (never larger than the query),
// the rest get no reply: a spoofed source can't turn the server into a
// reflector, nor starve the real owner of that address, who retries over
// TCP (not rate limited). SourceLimit can raise both limits for chosen
// sources, or lift the rate limit.
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
	"syscall"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// DialFunc opens a TCP connection to dst (the upstream resolver) routed as
// a connection from src to qname would be.
type DialFunc func(ctx context.Context, src netip.Addr, qname string, dst outbound.Addr) (net.Conn, error)

// DialKeyedFunc is DialFunc that also returns the route key (in RouteKey's
// format) of the route the connection actually took.
type DialKeyedFunc func(ctx context.Context, src netip.Addr, qname string, dst outbound.Addr) (net.Conn, string, error)

type Options struct {
	Dial DialFunc
	// DialKeyed, if set, is used instead of Dial. The server pools the
	// connection and caches the answer only when the returned key equals
	// the key the query was routed under, so a route change between
	// RouteKey and the dial (e.g. the kill switch flipping to direct) can't
	// leave a direct connection pooled, or an answer cached, under a
	// proxied route.
	DialKeyed DialKeyedFunc
	Upstream  string // ip:port or host:port; port defaults to 53

	// RouteKey, if set, returns a key identifying the route Dial would
	// take for (src, qname) to the upstream address dst. It must route
	// exactly as Dial does, dst included, or a pooled connection could be
	// reused for a query whose route differs. One idle upstream connection
	// per key is kept for up to IdleTimeout and reused for later queries
	// with the same key. Without it every query uses a fresh connection.
	// The route key also partitions the cache.
	RouteKey func(src netip.Addr, qname string, dst netip.Addr) string

	MaxInFlight    int           // concurrent upstream queries; default 64
	MaxPerSource   int           // per-source upstream queries and TCP conns; default 16
	RatePerSource  int           // per-source UDP queries per second; default 20
	TCPIdleTimeout time.Duration // client TCP read limit per query; default 3s
	Timeout        time.Duration // per-query upstream timeout; default 5s
	IdleTimeout    time.Duration // pooled connection lifetime; default 10s
	CacheSize      int           // entries; default 1024

	// SourceLimit, if set, returns the limits for queries from src instead
	// of MaxPerSource and RatePerSource (e.g. higher ones for a router that
	// forwards every LAN query). Zero means the default; a negative
	// maxInFlight also means the default, a negative ratePerSec means no
	// UDP rate limit for src. It is called for every query and must be
	// fast.
	SourceLimit func(src netip.Addr) (maxInFlight, ratePerSec int)

	Logf func(format string, args ...any)
}

type Server struct {
	opts  Options
	cache *cache
	sem   chan struct{}

	queries  perSource // upstream queries in flight
	tcpConns perSource // open client TCP conns
	udpRate  rateLimiter
	failLog  logLimiter

	mu       sync.Mutex
	upstream outbound.Addr
	upErr    error
	idle     map[string]idleConn
}

type idleConn struct {
	conn  net.Conn
	since time.Time // last use
	born  time.Time // dial time
}

// maxPooledAge caps how long one upstream connection is reused.
const maxPooledAge = 60 * time.Second

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
	if opts.MaxPerSource <= 0 {
		opts.MaxPerSource = 16
	}
	if opts.RatePerSource <= 0 {
		opts.RatePerSource = 20
	}
	if opts.TCPIdleTimeout <= 0 {
		opts.TCPIdleTimeout = 3 * time.Second
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

		udpRate: rateLimiter{b: map[netip.Addr]*bucket{}},
	}
	s.queries = perSource{max: s.maxInFlight, n: map[netip.Addr]int{}}
	s.tcpConns = perSource{max: s.maxInFlight, n: map[netip.Addr]int{}}
	s.SetUpstream(opts.Upstream)
	return s
}

// limits returns the in-flight cap and UDP rate for src (< 0: unlimited).
func (s *Server) limits(src netip.Addr) (maxInFlight, ratePerSec int) {
	if s.opts.SourceLimit != nil {
		maxInFlight, ratePerSec = s.opts.SourceLimit(src)
	}
	if maxInFlight <= 0 {
		maxInFlight = s.opts.MaxPerSource
	}
	if ratePerSec == 0 {
		ratePerSec = s.opts.RatePerSource
	}
	return maxInFlight, ratePerSec
}

func (s *Server) maxInFlight(src netip.Addr) int {
	n, _ := s.limits(src)
	return n
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
		if n < headerLen || n > maxQuery {
			continue
		}
		src := srcOf(from)
		_, rate := s.limits(src)
		switch s.udpRate.take(src, rate, time.Now()) {
		case rateDrop:
			continue // over the rate: no reply, so nothing to reflect
		case rateSlip:
			if resp := slipResponse(buf[:n]); resp != nil {
				pc.WriteTo(resp, from)
			}
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
			resp := s.handle(ctx, src, query)
			if resp == nil {
				return
			}
			pc.WriteTo(truncate(resp, udpLimit(query)), from)
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	conns := make(chan struct{}, 4*s.opts.MaxInFlight)
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return net.ErrClosed
			}
			// Out of file descriptors is temporary; returning would end the
			// whole process (same handling as inbound.serve).
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		src := srcOf(c.RemoteAddr())
		if !s.tcpConns.acquire(src) {
			c.Close()
			continue
		}
		select {
		case conns <- struct{}{}:
		default:
			s.tcpConns.release(src)
			c.Close()
			continue
		}
		go func() {
			defer func() { <-conns; s.tcpConns.release(src) }()
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
		c.SetReadDeadline(time.Now().Add(s.opts.TCPIdleTimeout))
		query, err := readMsg(c, maxQuery)
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
	up, upErr := s.upstreamAddr()
	key := s.routeKey(src, q.Name, up)
	variant, shared := cacheVariant(query, h, q)
	if shared {
		if resp := s.cache.get(query, q, key+variant); resp != nil {
			return resp
		}
	}
	if !s.queries.acquire(src) {
		return errorResponse(query, rcodeServFail) // not logged: a flood would fill the log
	}
	defer s.queries.release(src)
	resp, cacheable, err := s.exchange(ctx, src, query, q, up, upErr, key)
	if err != nil {
		if ok, dropped := s.failLog.allow(time.Now()); ok {
			if dropped > 0 {
				s.opts.Logf("dns: %d more failed queries not logged", dropped)
			}
			s.opts.Logf("dns: %s %s from %s: %v", q.Name, typeString(q.Type), src, err)
		}
		return errorResponse(query, rcodeServFail)
	}
	if cacheable && shared {
		s.cache.put(q, key+variant, resp)
	}
	return resp
}

func (s *Server) upstreamAddr() (outbound.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upstream, s.upErr
}

// routeKey identifies the route of a query for qname from src to up, for
// the connection pool and the cache ("" without RouteKey).
func (s *Server) routeKey(src netip.Addr, qname string, up outbound.Addr) string {
	if s.opts.RouteKey == nil {
		return ""
	}
	return s.opts.RouteKey(src, strings.ToLower(qname), up.IP) + "|" + up.String()
}

// Exchange sends query upstream (bypassing the cache) and returns the raw
// response. It waits at most Timeout, including the wait for a free slot.
func (s *Server) Exchange(ctx context.Context, src netip.Addr, query []byte) ([]byte, error) {
	_, q, err := parseQuestion(query)
	if err != nil {
		return nil, err
	}
	up, upErr := s.upstreamAddr()
	resp, _, err := s.exchange(ctx, src, query, q, up, upErr, s.routeKey(src, q.Name, up))
	return resp, err
}

// exchange is Exchange with the question, upstream and route key already
// worked out.
func (s *Server) exchange(ctx context.Context, src netip.Addr, query []byte, q question, up outbound.Addr, upErr error, key string) (resp []byte, cacheable bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()
	select {
	case s.sem <- struct{}{}:
	default:
		// All upstream slots are taken. A source already over its fair
		// share (slots / active sources) fails at once instead of queueing,
		// so a few devices sending queries that never get an answer cannot
		// keep every slot: the others get the slots as they free up.
		if s.maxInFlight(src) <= s.opts.MaxPerSource && s.queries.overShare(src, cap(s.sem)) {
			return nil, false, errors.New("all upstream slots busy and source over its share")
		}
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, false, fmt.Errorf("waiting for a free upstream slot: %w", ctx.Err())
		}
	}
	defer func() { <-s.sem }()

	if upErr != nil {
		return nil, false, upErr
	}

	// A pooled connection may have been closed by the upstream; retry
	// once on a fresh one.
	if ic, ok := s.takeIdle(key); ok {
		if resp, err := exchangeOn(ctx, ic.conn, query); err == nil {
			s.putIdle(key, ic.conn, ic.born)
			return resp, true, nil
		}
		ic.conn.Close()
	}
	c, dialKey, err := s.dial(ctx, src, q.Name, up)
	if err != nil {
		return nil, false, fmt.Errorf("dial upstream %s: %w", up, err)
	}
	resp, err = exchangeOn(ctx, c, query)
	if err != nil {
		c.Close()
		return nil, false, fmt.Errorf("upstream %s: %w", up, err)
	}
	if dialKey != key {
		// The route changed between keying and dialing: answer this query
		// but neither pool the connection nor cache the answer under key.
		c.Close()
		return resp, false, nil
	}
	s.putIdle(key, c, time.Now())
	return resp, true, nil
}

// dial opens an upstream connection and returns the route key it took.
// With plain Dial the key is recomputed right after dialing.
func (s *Server) dial(ctx context.Context, src netip.Addr, qname string, up outbound.Addr) (net.Conn, string, error) {
	qname = strings.ToLower(qname)
	if s.opts.DialKeyed != nil {
		c, k, err := s.opts.DialKeyed(ctx, src, qname, up)
		if err != nil || s.opts.RouteKey == nil {
			return c, "", err
		}
		return c, k + "|" + up.String(), nil
	}
	c, err := s.opts.Dial(ctx, src, qname, up)
	return c, s.routeKey(src, qname, up), err
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
	_, q, err := parseQuestion(query)
	if err != nil {
		return nil, err
	}
	for {
		resp, err := readMsg(c, 0xffff)
		if err != nil {
			return nil, err
		}
		if answers(query, q, resp) {
			if !stop() {
				return nil, ctx.Err() // deadline was poisoned; don't reuse c
			}
			c.SetDeadline(time.Time{})
			return resp, nil
		}
		// A stale answer to an earlier, timed-out query: skip it.
	}
}

// answers reports whether resp is a response to query: same ID and the
// same question (an error reply may omit the question).
func answers(query []byte, q question, resp []byte) bool {
	h, err := parseHeader(resp)
	if err != nil || h.Flags&flagQR == 0 || h.ID != binary.BigEndian.Uint16(query) {
		return false
	}
	if h.QDCount == 0 {
		return h.rcode() != rcodeNoError
	}
	_, rq, err := parseQuestion(resp)
	return err == nil && keyOf(rq) == keyOf(q)
}

func (s *Server) takeIdle(key string) (idleConn, bool) {
	if key == "" {
		return idleConn{}, false
	}
	s.mu.Lock()
	ic, ok := s.idle[key]
	delete(s.idle, key)
	s.mu.Unlock()
	if !ok {
		return idleConn{}, false
	}
	if time.Since(ic.since) > s.opts.IdleTimeout || time.Since(ic.born) > maxPooledAge {
		ic.conn.Close()
		return idleConn{}, false
	}
	return ic, true
}

// putIdle pools c under key. born is when c was dialed: a pooled
// connection is retired maxPooledAge after it was opened however often it
// is reused, so a route or server change is picked up within that time.
func (s *Server) putIdle(key string, c net.Conn, born time.Time) {
	if key == "" {
		c.Close()
		return
	}
	s.mu.Lock()
	old, had := s.idle[key]
	s.idle[key] = idleConn{conn: c, since: time.Now(), born: born}
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

// maxQuery bounds a query from a client. Real queries are well under 512
// bytes; the rest of a larger one would be held in memory while it waits and
// then sent upstream through the proxy.
const maxQuery = 4096

func readMsg(r io.Reader, limit int) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > limit {
		return nil, errors.New("message too long")
	}
	msg := make([]byte, n)
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

// perSource counts something per source (IPv4 address or IPv6 /64) up to
// max(src).
type perSource struct {
	mu  sync.Mutex
	max func(netip.Addr) int
	n   map[netip.Addr]int
}

func sourceKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}

func (p *perSource) acquire(ip netip.Addr) bool {
	k, limit := sourceKey(ip), p.max(ip)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n[k] >= limit {
		return false
	}
	p.n[k]++
	return true
}

// overShare reports whether ip holds more than total / active sources.
func (p *perSource) overShare(ip netip.Addr, total int) bool {
	k := sourceKey(ip)
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.n) > 0 && p.n[k] > total/len(p.n)
}

func (p *perSource) release(ip netip.Addr) {
	k := sourceKey(ip)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n[k]--; p.n[k] <= 0 {
		delete(p.n, k)
	}
}

// maxRateSources bounds the rate limiter's map. A bucket idle for
// rateIdle is full again (bursts last at most 2.5 s), so dropping it loses
// nothing.
const (
	maxRateSources = 4096
	rateIdle       = 5 * time.Second
)

// rateLimiter is a token bucket per source (IPv4 address or IPv6 /64).
type rateLimiter struct {
	mu        sync.Mutex
	b         map[netip.Addr]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
	over   uint // queries over the rate, for slipping every second one
}

// rateVerdict says what to do with a UDP query.
type rateVerdict int

const (
	rateAllow rateVerdict = iota // answer it
	rateSlip                     // over the rate: answer with TC set only
	rateDrop                     // over the rate: no reply
)

// take takes a token from ip's bucket, which refills at rate per second
// up to a burst of 2.5*rate. Every second query over the rate slips. A
// negative rate means no limit.
func (r *rateLimiter) take(ip netip.Addr, rate int, now time.Time) rateVerdict {
	if rate < 0 {
		return rateAllow
	}
	k := sourceKey(ip)
	burst := float64(max(rate*5/2, 1))
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.b[k]
	if b == nil {
		if len(r.b) >= maxRateSources {
			r.evictLocked(now)
		}
		b = &bucket{tokens: burst}
		r.b[k] = b
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*float64(rate))
	}
	b.last = now
	if b.tokens < 1 {
		if b.over++; b.over%2 == 0 {
			return rateSlip
		}
		return rateDrop
	}
	b.tokens--
	return rateAllow
}

// evictLocked makes room for one bucket: idle buckets go first (swept at
// most once a second, so a flood of new sources costs O(1) per query),
// else an arbitrary one, which only resets that source to a full burst.
func (r *rateLimiter) evictLocked(now time.Time) {
	if now.Sub(r.lastSweep) >= time.Second {
		r.lastSweep = now
		for k, b := range r.b {
			if now.Sub(b.last) >= rateIdle {
				delete(r.b, k)
			}
		}
	}
	for k := range r.b {
		if len(r.b) < maxRateSources {
			return
		}
		delete(r.b, k)
	}
}

// Failed queries are logged at most failLogBurst times per failLogWindow.
// While a route is blocked or every proxy is down, each LAN query fails, and
// a line per query would flood the router's log.
const (
	failLogBurst  = 10
	failLogWindow = 10 * time.Second
)

type logLimiter struct {
	mu      sync.Mutex
	start   time.Time
	n       int
	dropped int
}

// allow reports whether one more line may be logged now. With the first
// line of a new window it also returns how many lines were dropped since
// the last one that was logged.
func (l *logLimiter) allow(now time.Time) (ok bool, dropped int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.start) >= failLogWindow {
		l.start, l.n = now, 0
	}
	if l.n >= failLogBurst {
		l.dropped++
		return false, 0
	}
	l.n++
	dropped, l.dropped = l.dropped, 0
	return true, dropped
}
