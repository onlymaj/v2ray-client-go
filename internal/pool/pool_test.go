package pool

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeConn struct {
	net.Conn
	id     int
	closed atomic.Bool
}

func (c *fakeConn) Close() error { c.closed.Store(true); return nil }

type fakeDialer struct {
	mu    sync.Mutex
	n     int
	conns []*fakeConn
	fail  bool
}

func (d *fakeDialer) dial(ctx context.Context) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return nil, errors.New("fail")
	}
	d.n++
	c := &fakeConn{id: d.n}
	d.conns = append(d.conns, c)
	return c, nil
}

func (d *fakeDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newTest() (*Pool, *fakeDialer, *clock) {
	d := &fakeDialer{}
	clk := &clock{t: time.Unix(1000, 0)}
	p := New(d.dial)
	p.now = clk.now
	return p, d, clk
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestNoWarmingOnFirstUse(t *testing.T) {
	p, d, _ := newTest()
	defer p.Close()
	if _, _, err := p.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if d.count() != 1 || p.Len() != 0 {
		t.Fatalf("dials=%d idle=%d, want 1/0", d.count(), p.Len())
	}
}

func TestWarmAndReuse(t *testing.T) {
	p, d, clk := newTest()
	defer p.Close()
	ctx := context.Background()
	p.Get(ctx)
	clk.add(time.Second)
	p.Get(ctx) // busy: refill to 2
	waitFor(t, func() bool { return p.Len() == 2 })
	if d.count() != 4 {
		t.Fatalf("dials=%d, want 4", d.count())
	}
	p.mu.Lock()
	newest := p.idle[1].c
	p.mu.Unlock()
	c, reused, _ := p.Get(ctx)
	if c != newest || !reused {
		t.Fatalf("got conn %d, want newest warm conn", c.(*fakeConn).id)
	}
	waitFor(t, func() bool { return p.Len() == 2 })
}

func TestStaleConnNotUsed(t *testing.T) {
	p, _, clk := newTest()
	defer p.Close()
	ctx := context.Background()
	p.Get(ctx)
	p.Get(ctx)
	waitFor(t, func() bool { return p.Len() == 2 })
	clk.add(MaxAge + time.Second)
	p.mu.Lock()
	stale := []net.Conn{p.idle[0].c, p.idle[1].c}
	p.mu.Unlock()
	c, reused, _ := p.Get(ctx)
	if reused || c == stale[0] || c == stale[1] {
		t.Fatal("got a stale conn")
	}
	for _, s := range stale {
		if !s.(*fakeConn).closed.Load() {
			t.Fatalf("stale conn %d not closed", s.(*fakeConn).id)
		}
	}
}

func TestSweepAndClose(t *testing.T) {
	p, d, _ := newTest()
	p.ttl = 30 * time.Millisecond
	p.now = time.Now
	ctx := context.Background()
	p.Get(ctx)
	p.Get(ctx)
	waitFor(t, func() bool { return p.Len() > 0 })
	waitFor(t, func() bool { return p.Len() == 0 })
	if d.count() < 3 {
		t.Fatal("no warm conns dialed")
	}
	p.Close()
	if _, _, err := p.Get(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDialErrorStopsFill(t *testing.T) {
	p, d, _ := newTest()
	defer p.Close()
	ctx := context.Background()
	p.Get(ctx)
	d.mu.Lock()
	d.fail = true
	d.mu.Unlock()
	if _, _, err := p.Get(ctx); err == nil {
		t.Fatal("want error")
	}
	time.Sleep(20 * time.Millisecond)
	if p.Len() != 0 {
		t.Fatal("pool filled despite errors")
	}
}
