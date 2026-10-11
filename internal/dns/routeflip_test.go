package dns

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

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
