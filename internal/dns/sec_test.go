package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// A label containing '.' must not alias the dotted name in the cache key.
func TestDottedLabelRejected(t *testing.T) {
	q := buildQuery(1, "x", typeA, 0)
	q = append(q[:headerLen], append([]byte{8}, "bank.com"...)...)
	q = append(q, 0, 0, typeA, 0, 1)
	if _, _, err := parseQuestion(q); err == nil {
		t.Fatal("label with '.' accepted")
	}
	for _, bad := range []string{"a\\b", "a b", "a\x00", "\xc3\xa9"} {
		q := append(append([]byte(nil), q[:headerLen]...), byte(len(bad)))
		q = append(append(q, bad...), 0, 0, typeA, 0, 1)
		if _, _, err := parseQuestion(q); err == nil {
			t.Errorf("label %q accepted", bad)
		}
	}
	if _, _, err := parseQuestion(buildQuery(1, "_dmarc.Ex-1.com", typeA, 0)); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
}

// Upstream responses must carry the query's ID, QR and question.
func TestAnswersMatchesQuestion(t *testing.T) {
	query := buildQuery(7, "a.example", typeA, 0)
	_, q, _ := parseQuestion(query)
	if !answers(query, q, buildAResponse(query, 60)) {
		t.Fatal("matching response rejected")
	}
	if answers(query, q, buildAResponse(buildQuery(7, "b.example", typeA, 0), 60)) {
		t.Fatal("response for another name accepted")
	}
	if answers(query, q, buildAResponse(buildQuery(8, "a.example", typeA, 0), 60)) {
		t.Fatal("response with another ID accepted")
	}
	if answers(query, q, query) {
		t.Fatal("query (QR=0) accepted as response")
	}
	formerr := append([]byte(nil), query[:headerLen]...)
	binary.BigEndian.PutUint16(formerr[2:], flagQR|rcodeFormErr)
	binary.BigEndian.PutUint16(formerr[4:], 0)
	if !answers(query, q, formerr) {
		t.Fatal("question-less error reply rejected")
	}
}

// RouteKey must see the upstream address Dial routes with.
func TestRouteKeyGetsUpstream(t *testing.T) {
	var got netip.Addr
	s := New(Options{
		Upstream: "192.0.2.53",
		Dial: func(context.Context, netip.Addr, string, outbound.Addr) (net.Conn, error) {
			return nil, errors.New("no")
		},
		RouteKey: func(_ netip.Addr, _ string, dst netip.Addr) string { got = dst; return "k" },
	})
	s.Exchange(context.Background(), netip.Addr{}, buildQuery(1, "a.example", typeA, 0))
	if got != netip.MustParseAddr("192.0.2.53") {
		t.Fatalf("RouteKey dst = %v", got)
	}
}

func rcodeOf(t *testing.T, resp []byte) int {
	t.Helper()
	h, err := parseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	return h.rcode()
}

// Cached answers are per route: a blocked source gets no answer cached by
// another, and a proxied source gets no answer fetched direct.
func TestCachePerRoute(t *testing.T) {
	up := newFakeUpstream(t)
	blocked, proxied := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")
	route := func(src netip.Addr) string {
		switch src {
		case blocked:
			return "block"
		case proxied:
			return "proxy"
		}
		return "direct"
	}
	rec := &dialRecord{}
	dial := directDial(rec)
	s := New(Options{
		Upstream: up.ln.Addr().String(),
		Dial: func(ctx context.Context, src netip.Addr, qname string, dst outbound.Addr) (net.Conn, error) {
			if route(src) == "block" {
				return nil, errors.New("blocked")
			}
			return dial(ctx, src, qname, dst)
		},
		RouteKey: func(src netip.Addr, _ string, _ netip.Addr) string { return route(src) },
	})
	t.Cleanup(s.closeIdle) // pooled upstream conns, before the upstream stops
	ctx := context.Background()
	q := buildQuery(1, "shared.example", typeA, 0)
	if rc := rcodeOf(t, s.handle(ctx, netip.MustParseAddr("10.0.0.1"), q)); rc != rcodeNoError {
		t.Fatalf("direct rcode %d", rc)
	}
	if rc := rcodeOf(t, s.handle(ctx, blocked, q)); rc != rcodeServFail {
		t.Fatalf("blocked source got rcode %d from the cache", rc)
	}
	if rc := rcodeOf(t, s.handle(ctx, proxied, q)); rc != rcodeNoError {
		t.Fatalf("proxied rcode %d", rc)
	}
	if n := up.queries.Load(); n != 2 {
		t.Fatalf("upstream queries %d, want 2 (proxied must not reuse the direct answer)", n)
	}
	s.handle(ctx, proxied, q)
	if n := up.queries.Load(); n != 2 {
		t.Fatalf("upstream queries %d, want 2 (same route must hit the cache)", n)
	}
}

// One source cannot hold more than MaxPerSource upstream queries.
func TestPerSourceQueryCap(t *testing.T) {
	up := newFakeUpstream(t)
	up.delay = 500 * time.Millisecond
	s := New(Options{Upstream: up.ln.Addr().String(), Dial: directDial(&dialRecord{}), MaxPerSource: 2})
	ctx := context.Background()
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	for i := range 2 {
		go s.handle(ctx, a, buildQuery(1, "slow"+string(rune('a'+i))+".example", typeA, 0))
	}
	for i := 0; up.queries.Load() < 2 && i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	if rc := rcodeOf(t, s.handle(ctx, a, buildQuery(1, "over.example", typeA, 0))); rc != rcodeServFail {
		t.Fatalf("query over the per-source cap: rcode %d", rc)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("query over the per-source cap was not refused at once")
	}
	if rc := rcodeOf(t, s.handle(ctx, b, buildQuery(1, "other.example", typeA, 0))); rc != rcodeNoError {
		t.Fatalf("other source: rcode %d", rc)
	}
}

// One source cannot hold more than MaxPerSource TCP conns, and idle TCP
// clients are dropped after TCPIdleTimeout.
func TestPerSourceTCPCap(t *testing.T) {
	up := newFakeUpstream(t)
	s := New(Options{
		Upstream: up.ln.Addr().String(), Dial: directDial(&dialRecord{}),
		MaxPerSource: 2, TCPIdleTimeout: 300 * time.Millisecond,
	})
	addr := startServer(t, s)
	dialFrom := func(src string) net.Conn {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	query := func(c net.Conn) error {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if err := writeMsg(c, buildQuery(1, "a.example", typeA, 0)); err != nil {
			return err
		}
		_, err := readMsg(c)
		return err
	}
	held := []net.Conn{dialFrom("127.0.0.1"), dialFrom("127.0.0.1")}
	time.Sleep(50 * time.Millisecond)
	if err := query(dialFrom("127.0.0.1")); err == nil {
		t.Fatal("TCP conn over the per-source cap was served")
	}
	if err := query(dialFrom("127.0.0.2")); err != nil {
		t.Fatalf("other source: %v", err)
	}
	held[0].SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := held[0].Read(make([]byte, 1)); err == nil || time.Since(start) > time.Second {
		t.Fatalf("idle TCP client not dropped: %v after %v", err, time.Since(start))
	}
}
