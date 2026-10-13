package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
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
		_, err := readMsg(c, 0xffff)
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

// udpReplies sends n copies of q from src to the server at addr and
// counts the full replies and the slipped (TC, header + question) ones,
// which must not be longer than q.
func udpReplies(t *testing.T, src, addr string, q []byte, n int) (full, tc int) {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(src)}, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range n {
		c.Write(q)
	}
	buf := make([]byte, 65535)
	for {
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		m, err := c.Read(buf)
		if err != nil {
			return full, tc
		}
		h, _ := parseHeader(buf[:m])
		if h.Flags&flagTC == 0 {
			full++
			continue
		}
		tc++
		if m > len(q) || h.ANCount != 0 || h.ARCount != 0 || h.Flags&flagQR == 0 {
			t.Errorf("slip reply: %d bytes (query %d), header %+v", m, len(q), h)
		}
	}
}

// allow reports whether take lets the query through.
func (r *rateLimiter) allow(ip netip.Addr, rate int, now time.Time) bool {
	return r.take(ip, rate, now) == rateAllow
}

// UDP replies, cache hits included, are rate limited per source; every
// second query over the rate gets a TC reply, the rest none. SourceLimit
// raises the rate for a source.
func TestUDPRateLimit(t *testing.T) {
	up := newFakeUpstream(t)
	router := netip.MustParseAddr("127.0.0.3")
	s := New(Options{
		Upstream: up.ln.Addr().String(), Dial: directDial(&dialRecord{}),
		RatePerSource: 2, // burst 5
		SourceLimit: func(src netip.Addr) (int, int) {
			if src == router {
				return 0, 1000
			}
			return 0, 0
		},
	})
	addr := startServer(t, s)
	q := buildQuery(1, "a.example", typeA, 0)
	if n, _ := udpReplies(t, "127.0.0.1", addr, q, 1); n != 1 {
		t.Fatalf("first query: %d replies", n)
	}
	if n, tc := udpReplies(t, "127.0.0.1", addr, q, 20); n > 4 || tc < 6 || tc > 10 {
		t.Fatalf("%d cached and %d TC replies over the rate, want <= 4 and ~8", n, tc)
	}
	if n := up.queries.Load(); n != 1 {
		t.Fatalf("upstream queries %d, want 1 (the rest were cache hits)", n)
	}
	if n, _ := udpReplies(t, "127.0.0.2", addr, q, 1); n != 1 {
		t.Fatal("other source limited")
	}
	if n, _ := udpReplies(t, router.String(), addr, q, 20); n != 20 {
		t.Fatalf("SourceLimit source got %d of 20 replies", n)
	}
}

func TestRateLimiterRefillAndBound(t *testing.T) {
	var r rateLimiter
	r.b = map[netip.Addr]*bucket{}
	now := time.Unix(1000, 0)
	a := netip.MustParseAddr("10.0.0.1")
	for i := range 2 { // rate 1: burst 2
		if !r.allow(a, 1, now) {
			t.Fatalf("query %d within the burst refused", i)
		}
	}
	if r.allow(a, 1, now) {
		t.Fatal("query over the burst allowed")
	}
	if !r.allow(a, 1, now.Add(time.Second)) {
		t.Fatal("bucket not refilled")
	}
	// IPv6 sources share a bucket per /64.
	b6, c6 := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	r.allow(b6, 1, now)
	r.allow(c6, 1, now)
	if r.allow(b6, 1, now) {
		t.Fatal("IPv6 /64 not shared")
	}

	// A flood of new sources keeps the map bounded.
	for i := range 3 * maxRateSources {
		ip := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		r.allow(ip, 20, now)
	}
	if len(r.b) > maxRateSources {
		t.Fatalf("limiter holds %d sources, max %d", len(r.b), maxRateSources)
	}
	// Idle buckets are swept first.
	later := now.Add(rateIdle + time.Second)
	r.allow(netip.MustParseAddr("10.2.0.1"), 20, later)
	if len(r.b) != 1 {
		t.Fatalf("idle buckets not swept: %d left", len(r.b))
	}
}

// SourceLimit sets the per-source in-flight cap for upstream queries and
// TCP conns.
func TestSourceLimitInFlight(t *testing.T) {
	router := netip.MustParseAddr("192.168.88.1")
	s := New(Options{
		MaxPerSource: 2,
		SourceLimit: func(src netip.Addr) (int, int) {
			if src == router {
				return 5, 0
			}
			return 0, 0
		},
	})
	other := netip.MustParseAddr("192.168.88.2")
	for _, p := range []*perSource{&s.queries, &s.tcpConns} {
		for i := range 5 {
			if !p.acquire(router) {
				t.Fatalf("router slot %d refused", i)
			}
		}
		if p.acquire(router) {
			t.Fatal("router over its limit")
		}
		for range 2 {
			if !p.acquire(other) {
				t.Fatal("default slot refused")
			}
		}
		if p.acquire(other) {
			t.Fatal("other source over the default limit")
		}
	}
}

// A spoofer who drains a victim's bucket can't starve it: the victim still
// gets TC replies and its query succeeds over TCP, which the UDP rate limit
// doesn't cover.
func TestSlipVictimFallsBackToTCP(t *testing.T) {
	up := newFakeUpstream(t)
	s := New(Options{
		Upstream: up.ln.Addr().String(), Dial: directDial(&dialRecord{}),
		RatePerSource: 1, // burst 2
	})
	addr := startServer(t, s)
	q := buildQuery(7, "victim.example", typeA, 4096)
	udpReplies(t, "127.0.0.1", addr, q, 50) // the spoofed flood
	full, tc := udpReplies(t, "127.0.0.1", addr, q, 4)
	if full != 0 || tc == 0 {
		t.Fatalf("victim on a drained bucket: %d full, %d TC replies", full, tc)
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeMsg(c, q); err != nil {
		t.Fatal(err)
	}
	resp, err := readMsg(c, 0xffff)
	if err != nil {
		t.Fatalf("TCP fallback: %v", err)
	}
	if h, _ := parseHeader(resp); h.Flags&flagTC != 0 || h.ANCount == 0 {
		t.Fatalf("TCP fallback answer: %+v", h)
	}
}

// A slip reply is header + question with QR and TC set, never longer than
// the query; responses and malformed queries get none.
func TestSlipResponse(t *testing.T) {
	for _, q := range [][]byte{
		buildQuery(1, "a.example", typeA, 0),
		buildQuery(2, "a.example", typeA, 4096),
		buildQuery(3, "a-much-longer-label.sub.example", 28, 1232),
	} {
		r := slipResponse(q)
		h, err := parseHeader(r)
		if err != nil || len(r) > len(q) || h.Flags&(flagQR|flagTC) != flagQR|flagTC ||
			h.ID != binary.BigEndian.Uint16(q) || h.QDCount != 1 || h.ANCount+h.NSCount+h.ARCount != 0 {
			t.Fatalf("slip for %d-byte query: %d bytes, %+v, %v", len(q), len(r), h, err)
		}
	}
	resp := buildQuery(4, "a.example", typeA, 0)
	binary.BigEndian.PutUint16(resp[2:], flagQR)
	for _, m := range [][]byte{resp, make([]byte, headerLen), {1, 2, 3}} {
		if r := slipResponse(m); r != nil {
			t.Fatalf("slip reply to %x: %x", m, r)
		}
	}
}

// A negative rate from SourceLimit lifts the UDP rate limit for a source.
func TestUnlimitedSource(t *testing.T) {
	var r rateLimiter
	r.b = map[netip.Addr]*bucket{}
	now := time.Unix(1000, 0)
	a := netip.MustParseAddr("192.168.88.1")
	for i := range 10000 {
		if v := r.take(a, -1, now); v != rateAllow {
			t.Fatalf("unlimited source query %d: verdict %d", i, v)
		}
	}
	if len(r.b) != 0 {
		t.Fatal("unlimited source got a bucket")
	}

	up := newFakeUpstream(t)
	router := netip.MustParseAddr("127.0.0.3")
	s := New(Options{
		Upstream: up.ln.Addr().String(), Dial: directDial(&dialRecord{}),
		RatePerSource: 1,
		SourceLimit: func(src netip.Addr) (int, int) {
			if src == router {
				return 0, -1
			}
			return 0, 0
		},
	})
	if _, rate := s.limits(router); rate >= 0 {
		t.Fatalf("router rate %d, want unlimited", rate)
	}
	addr := startServer(t, s)
	q := buildQuery(1, "a.example", typeA, 0)
	if n, tc := udpReplies(t, router.String(), addr, q, 100); n != 100 || tc != 0 {
		t.Fatalf("unlimited source: %d full, %d TC of 100", n, tc)
	}
}

// Round 7 stress test: with a blocked route every query failed and logged
// one line, about 100 lines per second. Failed queries may log only
// failLogBurst lines per window, then one count of the lines left out.
func TestFailedQueryLogIsRateLimited(t *testing.T) {
	var lines []string
	s := New(Options{
		Dial: func(context.Context, netip.Addr, string, outbound.Addr) (net.Conn, error) {
			return nil, errors.New("dispatch: blocked")
		},
		Upstream: "192.0.2.1:53",
		Logf:     func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) },
	})
	for i := range 200 {
		r := s.handle(context.Background(), netip.MustParseAddr("192.168.88.10"), buildQuery(uint16(i), fmt.Sprintf("h%d.example", i), typeA, 0))
		if h, _ := parseHeader(r); h.rcode() != rcodeServFail {
			t.Fatalf("query %d: got %+v", i, h)
		}
	}
	if len(lines) != failLogBurst {
		t.Fatalf("200 failed queries logged %d lines, want %d", len(lines), failLogBurst)
	}

	var l logLimiter
	now := time.Now()
	for range failLogBurst + 7 {
		l.allow(now)
	}
	if ok, dropped := l.allow(now.Add(failLogWindow)); !ok || dropped != 7 {
		t.Fatalf("next window: ok=%v dropped=%d, want true and 7", ok, dropped)
	}
}

// Round 8: the cache was bounded by entry count only, so 1024 names with
// 60 KB answers pinned about 64 MB. Large responses are not cached.
func TestLargeResponseNotCached(t *testing.T) {
	c := newCache(8)
	q := buildQuery(1, "big.example", typeA, 0)
	_, qq, _ := parseQuestion(q)
	ttls := make([]uint32, 400) // 16 bytes per record: 6.4 KB
	for i := range ttls {
		ttls[i] = 300
	}
	c.put(qq, "", buildAResponse(q, ttls...))
	if c.len() != 0 {
		t.Fatal("response over maxCachedResp was cached")
	}
	c.put(qq, "", buildAResponse(q, 300))
	if c.len() != 1 {
		t.Fatal("small response not cached")
	}
}

// Round 8: an answer to a query with an EDNS Client Subnet option or the CD
// bit is tailored to that query and must not be cached for other clients;
// DO and non-DO answers are cached apart.
func TestCacheVariant(t *testing.T) {
	plain := buildQuery(1, "cdn.example", typeA, 1232)
	withOpt := func(ttl uint32, opt []byte) []byte {
		q := append([]byte(nil), plain[:len(plain)-6]...)
		q = u16(u32(q, ttl), uint16(len(opt)))
		return append(q, opt...)
	}
	cd := append([]byte(nil), plain...)
	cd[3] |= flagCD
	noRD := append([]byte(nil), plain...)
	noRD[2] &^= flagRD >> 8
	status := append([]byte(nil), plain...)
	status[2] |= 2 << 3 // opcode STATUS
	for _, tc := range []struct {
		name    string
		q       []byte
		variant string
		shared  bool
	}{
		{"plain", plain, "", true},
		{"no edns", buildQuery(1, "cdn.example", typeA, 0), "", true},
		{"do", withOpt(1<<15, nil), "|do", true},
		{"cookie", withOpt(0, []byte{0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}), "", false}, // round 9
		{"padding", withOpt(0, []byte{0, 12, 0, 2, 0, 0}), "", true},
		{"ecs", withOpt(0, []byte{0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113}), "", false},
		{"ecs after padding", withOpt(0, []byte{0, 12, 0, 2, 0, 0, 0, 8, 0, 4, 0, 1, 0, 0}), "", false},
		{"bad option length", withOpt(0, []byte{0, 10, 0, 9, 1}), "", false},
		{"cd", cd, "", false},
		{"private-use option", withOpt(0, []byte{0xfd, 0xe9, 0, 2, 1, 2}), "", false}, // round 15
		{"no rd", noRD, "", false},
		{"not a query", status, "", false},
	} {
		h, q, err := parseQuestion(tc.q)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if v, s := cacheVariant(tc.q, h, q); v != tc.variant || s != tc.shared {
			t.Errorf("%s: variant %q shared %v, want %q %v", tc.name, v, s, tc.variant, tc.shared)
		}
	}
}

// Round 10: four source addresses, each within the per-source cap, could
// hold every upstream slot with queries that never get an answer, so every
// other device waited out the timeout. With all slots taken, a source over
// its fair share now fails at once and the others get the freed slots.
func TestUpstreamSlotsFairShare(t *testing.T) {
	up := newFakeUpstream(t)
	up.delay = 500 * time.Millisecond
	s := New(Options{Upstream: up.ln.Addr().String(), Dial: directDial(&dialRecord{}), MaxInFlight: 4, MaxPerSource: 3})
	ctx := context.Background()
	a, b, c := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")
	for i, src := range []netip.Addr{a, a, b, b} {
		go s.handle(ctx, src, buildQuery(1, fmt.Sprintf("slow%d.example", i), typeA, 0))
	}
	for i := 0; up.queries.Load() < 4 && i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	other := make(chan int, 1)
	go func() { other <- rcodeOf(t, s.handle(ctx, c, buildQuery(1, "other.example", typeA, 0))) }()
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	if rc := rcodeOf(t, s.handle(ctx, a, buildQuery(1, "more.example", typeA, 0))); rc != rcodeServFail {
		t.Fatalf("source over its share with all slots busy: rcode %d", rc)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("source over its share queued for a slot")
	}
	if rc := <-other; rc != rcodeNoError {
		t.Fatalf("source within its share: rcode %d", rc)
	}
}

// Round 10: a client query could be 64 KB (the parser ignores bytes after
// the question); 256 of them waiting pinned 16 MB.
func TestClientQuerySizeBounded(t *testing.T) {
	big := append([]byte{0xff, 0xff}, make([]byte, 0xffff)...)
	if _, err := readMsg(bytes.NewReader(big), maxQuery); err == nil {
		t.Fatal("64 KB TCP query accepted")
	}
	if m, err := readMsg(bytes.NewReader(big), 0xffff); err != nil || len(m) != 0xffff {
		t.Fatalf("upstream-sized message refused: %v", err)
	}
}

type emfileListener struct {
	net.Listener
	calls atomic.Int32
	done  chan struct{}
}

func (l *emfileListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) <= 3 {
		return nil, &net.OpError{Op: "accept", Err: syscall.EMFILE}
	}
	<-l.done
	return nil, net.ErrClosed
}

// Round 10: one "too many open files" from Accept ended the DNS server and,
// through it, the whole process.
func TestTCPAcceptSurvivesEMFILE(t *testing.T) {
	s := New(Options{Upstream: "192.0.2.1:53"})
	ln := &emfileListener{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	ret := make(chan error, 1)
	go func() { ret <- s.serveTCP(ctx, ln) }()
	for i := 0; ln.calls.Load() < 4 && i < 200; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case err := <-ret:
		t.Fatalf("serveTCP returned on EMFILE: %v", err)
	default:
	}
	if ln.calls.Load() < 4 {
		t.Fatal("Accept not retried after EMFILE")
	}
	cancel()
	close(ln.done)
	<-ret
}

// Round 11: with more sources in flight than upstream slots the fair share
// rounded down to 0, so every source was over it with a single query and
// got SERVFAIL at once instead of queueing.
func TestOverShareAllowsOneQuery(t *testing.T) {
	p := perSource{max: func(netip.Addr) int { return 16 }, n: map[netip.Addr]int{}}
	for i := range 100 {
		p.acquire(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
	}
	a := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	if p.overShare(a, 64) {
		t.Fatal("a source with one query is over its share")
	}
	p.acquire(a)
	if !p.overShare(a, 64) {
		t.Fatal("a source with two queries among 100 sources is within its share")
	}
}

// Round 11: a malformed packet with the response bit set was answered with
// FORMERR, which is itself such a packet: two servers (or a spoofed source)
// could bounce it without end.
func TestMalformedResponseNotAnswered(t *testing.T) {
	s := New(Options{Upstream: "192.0.2.1:53"})
	src := netip.MustParseAddr("192.168.88.10")
	noQuestion := []byte{0x12, 0x34, 0x80, 0x81, 0, 0, 0, 0, 0, 0, 0, 0}
	truncated := append([]byte{0x12, 0x34, 0x80, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, 5, 'a')
	for _, pkt := range [][]byte{noQuestion, truncated} {
		if r := s.handle(context.Background(), src, pkt); r != nil {
			t.Fatalf("reply % x to response packet % x", r, pkt)
		}
	}
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0} // a query still gets FORMERR
	if r := s.handle(context.Background(), src, query); r == nil {
		t.Fatal("malformed query not answered")
	}
}

// Round 18: an upstream answer could still be 64 KiB, held by each of the
// 64 queries in flight while its last byte was kept back.
func TestUpstreamAnswerSizeBounded(t *testing.T) {
	big := append([]byte{0xff, 0xff}, make([]byte, 0xffff)...)
	if _, err := readMsg(bytes.NewReader(big), maxAnswer); err == nil {
		t.Fatal("64 KiB upstream answer accepted")
	}
	ok := append([]byte{maxAnswer >> 8, 0}, make([]byte, maxAnswer)...)
	if m, err := readMsg(bytes.NewReader(ok), maxAnswer); err != nil || len(m) != maxAnswer {
		t.Fatalf("%d-byte answer refused: %v", maxAnswer, err)
	}
}

// Round 19: the test above passed without the fix, because it gave readMsg
// the limit itself. This one goes through the exchange.
func TestExchangeRefusesOversizeAnswer(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		readMsg(b, 0xffff)
		b.Write([]byte{0x50, 0x00}) // announces 20 KiB
		b.Write(make([]byte, 0x5000))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exchangeOn(ctx, a, buildQuery(1, "big.example", typeA, 0)); err == nil || err.Error() != "message too long" {
		t.Fatalf("20 KiB answer: %v", err)
	}
}

// Round 21: a response made of the smallest records was kept with an
// 8-byte offset for each, twice its size again: 8 MiB for a full cache.
func TestResponseWithManyRecordsNotCached(t *testing.T) {
	c := newCache(8)
	q := buildQuery(1, "many.example", typeA, 0)
	_, qq, _ := parseQuestion(q)
	ttls := make([]uint32, maxCachedRRs) // plus the OPT record; 16 bytes each, under maxCachedResp
	for i := range ttls {
		ttls[i] = 300
	}
	if resp := buildAResponse(q, ttls...); len(resp) > maxCachedResp {
		t.Fatalf("test response is %d bytes", len(resp))
	} else {
		c.put(qq, "", resp)
	}
	if c.len() != 0 {
		t.Fatalf("response with %d records was cached", len(ttls)+1)
	}
	c.put(qq, "", buildAResponse(q, ttls[:maxCachedRRs-1]...))
	if c.len() != 1 {
		t.Fatalf("response with %d records not cached", maxCachedRRs)
	}
}

// Round 21: the TCP listener's sockets kept the kernel's growing send
// buffer: a client that pipelined queries and stopped reading had 4 MiB
// queued on each connection.
func TestTCPClientSocketBuffersAreBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Options{Upstream: "192.0.2.1:53", TCPIdleTimeout: 200 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.serveTCP(ctx, spyListener{ln, t})
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.Read(make([]byte, 1)) // the server closes or the deadline passes
	if n := sndbuf.Load(); n <= 0 || n > 2*tcpBuf {
		t.Fatalf("SO_SNDBUF of the accepted connection is %d, want at most %d", n, 2*tcpBuf)
	}
}

var sndbuf atomic.Int64

// spyListener hands out conns that report their send buffer size when
// they are closed, which is after serveTCP has set it.
type spyListener struct {
	net.Listener
	t *testing.T
}

type spyConn struct{ *net.TCPConn }

func (l spyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return spyConn{c.(*net.TCPConn)}, nil
}

func (c spyConn) Close() error {
	if rc, err := c.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			n, _ := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
			sndbuf.Store(int64(n))
		})
	}
	return c.TCPConn.Close()
}
