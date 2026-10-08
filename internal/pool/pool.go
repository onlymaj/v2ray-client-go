// Package pool keeps a few pre-dialed, handshaken transport connections
// (TCP + TLS/Reality + WS) per proxy client so that a new proxied
// connection skips the transport handshake.
//
// VLESS and VMess need a fresh transport connection per proxied
// connection, so a pooled conn is consumed by Get and never returned.
// Warming only happens for clients carrying traffic: after a Get that
// follows another Get within TTL, the pool refills in the background, one
// dial at a time, up to Max. Idle conns older than TTL are closed.
package pool

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	DefaultMax  = 2
	DefaultTTL  = 60 * time.Second
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
	ttl  time.Duration
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
	return &Pool{dial: dial, max: DefaultMax, ttl: DefaultTTL, now: time.Now}
}

// Get returns a warm conn if one is fresh, otherwise dials a new one.
func (p *Pool) Get(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	now := p.now()
	busy := !p.lastGet.IsZero() && now.Sub(p.lastGet) < p.ttl
	p.lastGet = now
	var c net.Conn
	for len(p.idle) > 0 && c == nil {
		e := p.idle[len(p.idle)-1] // newest
		p.idle = p.idle[:len(p.idle)-1]
		if now.Sub(e.at) < p.ttl {
			c = e.c
		} else {
			e.c.Close()
		}
	}
	if busy && !p.closed && !p.filling && len(p.idle) < p.max {
		p.filling = true
		go p.fill()
	}
	p.mu.Unlock()
	if c != nil {
		return c, nil
	}
	return p.dial(ctx)
}

// fill dials until the pool holds max conns, the client goes quiet, or a
// dial fails.
func (p *Pool) fill() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		c, err := p.dial(ctx)
		cancel()
		p.mu.Lock()
		if err != nil || p.closed {
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
		if len(p.idle) >= p.max || now.Sub(p.lastGet) >= p.ttl {
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
	p.idle = nil
}
