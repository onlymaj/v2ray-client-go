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
// VLESS/VMess write their header lazily a dead conn is only noticed on
// first use. Get reports whether a conn was reused so the caller can retry
// once on a fresh dial (see internal/client).
package pool

import (
	"context"
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
	p.mu.Lock()
	now := p.now()
	busy := !p.lastGet.IsZero() && now.Sub(p.lastGet) < p.busy
	p.lastGet = now
	before := len(p.idle)
	for len(p.idle) > 0 && c == nil {
		e := p.idle[len(p.idle)-1] // newest
		p.idle = p.idle[:len(p.idle)-1]
		if now.Sub(e.at) < p.ttl {
			c = e.c
		} else {
			e.c.Close()
		}
	}
	warm.Add(int32(len(p.idle) - before))
	if busy && !p.closed && !p.filling && len(p.idle) < p.max {
		p.filling = true
		go p.fill()
	}
	p.mu.Unlock()
	if c != nil {
		return c, true, nil
	}
	c, err = p.dial(ctx)
	return c, false, err
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
