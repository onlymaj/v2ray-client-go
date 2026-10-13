package dns

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// Regression (round 5): if the route changes between keying a query and
// dialing (e.g. the kill switch flips a proxied route to direct), the
// connection must not be pooled and the answer must not be cached under the
// original key, or later queries keep reusing the wrong route.
func TestRouteFlipNotPooledOrCached(t *testing.T) {
	up := newFakeUpstream(t)
	var flips atomic.Int32
	flips.Store(1) // the first dial takes a different route
	var dials atomic.Int32
	dial := directDial(&dialRecord{})
	s := New(Options{
		Upstream: up.ln.Addr().String(),
		DialKeyed: func(ctx context.Context, src netip.Addr, qname string, dst outbound.Addr) (net.Conn, string, error) {
			dials.Add(1)
			c, err := dial(ctx, src, qname, dst)
			if flips.Add(-1) >= 0 {
				return c, "direct", err
			}
			return c, "proxy", err
		},
		RouteKey: func(netip.Addr, string, netip.Addr) string { return "proxy" },
	})
	t.Cleanup(s.closeIdle)
	ctx := context.Background()
	src := netip.MustParseAddr("10.0.0.1")
	q := buildQuery(1, "flip.example", typeA, 0)

	if rc := rcodeOf(t, s.handle(ctx, src, q)); rc != rcodeNoError {
		t.Fatalf("first query rcode %d", rc)
	}
	// Not cached: the second query goes upstream again, on a fresh dial
	// (nothing was pooled), now on the right route.
	if rc := rcodeOf(t, s.handle(ctx, src, q)); rc != rcodeNoError {
		t.Fatalf("second query rcode %d", rc)
	}
	if n := up.queries.Load(); n != 2 {
		t.Fatalf("upstream queries %d, want 2 (flipped answer must not be cached)", n)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("dials %d, want 2 (flipped conn must not be pooled)", n)
	}
	// Now the route matches: the answer is cached and the conn pooled.
	s.handle(ctx, src, q)
	if n := up.queries.Load(); n != 2 {
		t.Fatalf("upstream queries %d, want 2 (matching route must hit the cache)", n)
	}
	q2 := buildQuery(2, "other.example", typeA, 0)
	s.handle(ctx, src, q2)
	if n := dials.Load(); n != 2 {
		t.Fatalf("dials %d, want 2 (matching route must reuse the pooled conn)", n)
	}
}

// Round 15: a query in flight when the config was applied finished after
// the flush, so its answer was cached (up to an hour) and its connection
// pooled although both came through the old server of a client whose
// address had just been changed (same route key).
func TestInFlightQueryAcrossFlushNotPooledOrCached(t *testing.T) {
	up := newFakeUpstream(t)
	up.delay = 200 * time.Millisecond
	s := New(Options{
		Upstream: up.ln.Addr().String(),
		Dial:     directDial(&dialRecord{}),
		RouteKey: func(netip.Addr, string, netip.Addr) string { return "proxy" },
	})
	t.Cleanup(s.closeIdle)
	ctx := context.Background()
	src := netip.MustParseAddr("10.0.0.1")
	q := buildQuery(1, "inflight.example", typeA, 0)

	done := make(chan int, 1)
	go func() { done <- rcodeOf(t, s.handle(ctx, src, q)) }()
	time.Sleep(50 * time.Millisecond)
	s.SetUpstream(up.ln.Addr().String()) // what apply does on every config change
	s.Flush()
	if rc := <-done; rc != rcodeNoError {
		t.Fatalf("in-flight query rcode %d", rc)
	}
	s.handle(ctx, src, q)
	if n := up.queries.Load(); n != 2 {
		t.Fatalf("upstream queries %d, want 2 (answer from before the flush must not be cached)", n)
	}
	if n := up.conns.Load(); n != 2 {
		t.Fatalf("upstream conns %d, want 2 (conn from before the flush must not be pooled)", n)
	}
	s.handle(ctx, src, q)
	if n := up.queries.Load(); n != 2 {
		t.Fatalf("upstream queries %d, want 2 (later answers are cached again)", n)
	}
}

type lenOnly struct{ sent bool }

func (r *lenOnly) Read(p []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(p, []byte{0xff, 0xff}), nil
}

// Round 17: an upstream answer was allocated from its 2-byte length (up to
// 64 KiB) before any of it arrived.
func TestReadMsgAllocatesAsBytesArrive(t *testing.T) {
	if n := testing.AllocsPerRun(1, func() {}); n != 0 {
		t.Skip()
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 16 {
		if _, err := readMsg(&lenOnly{}, 0xffff); err == nil {
			t.Fatal("truncated message accepted")
		}
	}
	runtime.ReadMemStats(&after)
	if d := after.TotalAlloc - before.TotalAlloc; d > 16*(4<<10) {
		t.Fatalf("16 length-only answers allocated %d bytes", d)
	}
	msg := make([]byte, 2+5000)
	msg[0], msg[1] = 5000>>8, 5000&0xff
	msg[2+4999] = 7
	if got, err := readMsg(bytes.NewReader(msg), 0xffff); err != nil || len(got) != 5000 || got[4999] != 7 {
		t.Fatalf("5000-byte message: len %d err %v", len(got), err)
	}
}
