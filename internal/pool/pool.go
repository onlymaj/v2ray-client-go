// Package pool keeps a few pre-dialed, handshaken transport connections
// (TCP + TLS/Reality + WS) per proxy client so that a new proxied
// connection skips the transport handshake.
//
// VLESS and VMess need a fresh transport connection per proxied
// connection, so a pooled conn is consumed by Get and never returned.
// Warming only happens for clients carrying traffic: after a Get that
// follows another Get within BusyWindow (60s), the pool refills in the
// background, one dial at a time, up to Max.
//
// Idle conns are closed after MaxAge (30s, shorter than the 60s traffic
// window): servers, middleboxes and CDNs may drop idle conns, and because
// VLESS/VMess write their header lazily a dead conn would only be noticed
// on first use. Get looks at a conn that has waited before handing it out
// (see alive), and reports whether a conn was reused so the caller can
// still retry once on a fresh dial (see internal/client).
package pool

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MaxWarm bounds the warm conns of all pools together. Each pool is small,
// but there is one per client: a group that spreads connections over many
// clients kept two warm conns on every one of them, 2000 conns and 64 MiB
// at the client limit (round 21).
const MaxWarm = 32

var maxWarm atomic.Int32 // MaxWarm; tests lower it

func init() { maxWarm.Store(MaxWarm) }

var warm atomic.Int32 // idle conns in all pools

const (
	DefaultMax  = 2
	MaxAge      = 30 * time.Second
	BusyWindow  = 60 * time.Second
	dialTimeout = 10 * time.Second
)

type entry struct {
	c  net.Conn
	at time.Time
}

// Pool is safe for concurrent use.
type Pool struct {
	dial func(ctx context.Context) (net.Conn, error)
	max  int
	ttl  time.Duration    // MaxAge
	busy time.Duration    // BusyWindow
	now  func() time.Time // for tests

	mu      sync.Mutex
	idle    []entry // oldest first
	lastGet time.Time
	filling bool
	closed  bool
	timer   *time.Timer
}

// New returns a pool that opens transport conns with dial.
func New(dial func(ctx context.Context) (net.Conn, error)) *Pool {
	return &Pool{dial: dial, max: DefaultMax, ttl: MaxAge, busy: BusyWindow, now: time.Now}
}

// Get returns a warm conn if one is fresh (reused = true), otherwise dials
// a new one.
func (p *Pool) Get(ctx context.Context) (c net.Conn, reused bool, err error) {
	for first := true; ; first = false {
		p.mu.Lock()
		now := p.now()
		busy := false
		if first {
			busy = !p.lastGet.IsZero() && now.Sub(p.lastGet) < p.busy
			p.lastGet = now
		}
		before := len(p.idle)
		var age time.Duration
		for c = nil; len(p.idle) > 0 && c == nil; {
			e := p.idle[len(p.idle)-1] // newest
			p.idle = p.idle[:len(p.idle)-1]
			if age = now.Sub(e.at); age < p.ttl {
				c = e.c
			} else {
				e.c.Close()
			}
		}
		warm.Add(int32(len(p.idle) - before))
		// Beside this Get's own dial or use, not after it.
		if busy && !p.closed && !p.filling && len(p.idle) < p.max {
			p.filling = true
			go p.fill()
		}
		p.mu.Unlock()
		if c == nil {
			break
		}
		if age < probeAfter || alive(c) {
			return c, true, nil
		}
		c.Close()
	}
	c, err = p.dial(ctx)
	return c, false, err
}

// probeAfter is how long a conn must have waited before Get looks whether
// the server has closed it.
const probeAfter = time.Second

// alive reports whether an idle conn is still open: a read of a
// millisecond finds nothing and times out. A server may close a conn that
// sends nothing for a few seconds (older Xray and v2fly after 4 s, a CDN),
// and the first Write on it still succeeds. The caller's retry does not
// send a plaintext request a second time, so every such connection failed:
// the first plain HTTP or SSH connection after a quiet moment (round 26).
// A conn that has data is not what was left here and is not used either.
//
// A read whose deadline has passed before it starts returns the timeout
// without looking at the socket, and a goroutine can be held up for more
// than the millisecond (the collector, four busy cores): such a read says
// nothing and is done again (round 27). A conn that knows better how to
// look, one whose Read does not reach the socket yet, has its own Alive.
func alive(c net.Conn) bool {
	if a, ok := c.(interface{ Alive() bool }); ok {
		return a.Alive()
	}
	var b [1]byte
	for range 3 {
		dl := time.Now().Add(time.Millisecond)
		if c.SetReadDeadline(dl) != nil {
			return false
		}
		start := time.Now()
		n, err := c.Read(b[:])
		var ne net.Error
		if n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
			return false
		}
		if dl.Sub(start) > 200*time.Microsecond {
			return c.SetReadDeadline(time.Time{}) == nil
		}
	}
	return false // could not tell; a fresh dial is always right
}

// fill dials until the pool holds max conns, the client goes quiet, or a
// dial fails.
func (p *Pool) fill() {
	for {
		// The place is taken before the dial: pools that only looked at
		// the counter all dialed during a burst and went far over the
		// limit (round 22).
		if warm.Add(1) > maxWarm.Load() {
			warm.Add(-1)
			p.mu.Lock()
			p.filling = false
			p.mu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		c, err := p.dial(ctx)
		cancel()
		p.mu.Lock()
		if err != nil || p.closed {
			warm.Add(-1)
			p.filling = false
			p.mu.Unlock()
			if c != nil {
				c.Close()
			}
			return
		}
		now := p.now()
		p.idle = append(p.idle, entry{c, now})
		if p.timer == nil {
			p.timer = time.AfterFunc(p.ttl, p.sweep)
		}
		if len(p.idle) >= p.max || now.Sub(p.lastGet) >= p.busy {
			p.filling = false
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
	}
}

// sweep closes expired idle conns and reschedules itself for the oldest
// remaining one.
func (p *Pool) sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timer = nil
	if p.closed {
		return
	}
	now := p.now()
	defer func(before int) { warm.Add(int32(len(p.idle) - before)) }(len(p.idle))
	n := 0
	for _, e := range p.idle {
		if now.Sub(e.at) >= p.ttl {
			e.c.Close()
			n++
		}
	}
	p.idle = append(p.idle[:0], p.idle[n:]...)
	if len(p.idle) > 0 {
		p.timer = time.AfterFunc(p.ttl-now.Sub(p.idle[0].at), p.sweep)
	}
}

// Len returns the number of idle conns.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

// Close closes all idle conns and stops warming. Get keeps working but
// always dials.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	for _, e := range p.idle {
		e.c.Close()
	}
	warm.Add(int32(-len(p.idle)))
	p.idle = nil
}
