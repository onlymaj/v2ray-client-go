package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

const typeA = 1

func encName(name string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func u16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func u32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

// buildQuery returns a query for name/qtype; ednsSize > 0 adds an OPT RR.
func buildQuery(id uint16, name string, qtype uint16, ednsSize uint16) []byte {
	b := u16(nil, id)
	b = u16(b, flagRD)
	b = u16(b, 1)
	b = u16(b, 0)
	b = u16(b, 0)
	if ednsSize > 0 {
		b = u16(b, 1)
	} else {
		b = u16(b, 0)
	}
	b = append(b, encName(name)...)
	b = u16(b, qtype)
	b = u16(b, 1)
	if ednsSize > 0 {
		b = append(b, 0)
		b = u16(b, typeOPT)
		b = u16(b, ednsSize)
		b = u32(b, 0)
		b = u16(b, 0)
	}
	return b
}

// buildAResponse answers query with n A records whose owner names are
// compression pointers to the question name, and an OPT record that must
// not be TTL-adjusted.
func buildAResponse(query []byte, ttls ...uint32) []byte {
	_, q, err := parseQuestion(query)
	if err != nil {
		panic(err)
	}
	b := append([]byte(nil), query[:q.End]...)
	binary.BigEndian.PutUint16(b[2:], flagQR|flagRD|flagRA)
	binary.BigEndian.PutUint16(b[6:], uint16(len(ttls)))
	binary.BigEndian.PutUint16(b[8:], 0)
	binary.BigEndian.PutUint16(b[10:], 1)
	for i, ttl := range ttls {
		b = append(b, 0xc0, headerLen) // pointer to question name
		b = u16(b, typeA)
		b = u16(b, 1)
		b = u32(b, ttl)
		b = u16(b, 4)
		b = append(b, 10, 0, 0, byte(i+1))
	}
	b = append(b, 0)
	b = u16(b, typeOPT)
	b = u16(b, 1232)
	b = u32(b, 0)
	b = u16(b, 0)
	return b
}

// buildNXDomain answers with NXDOMAIN and an SOA in authority whose MNAME
// uses a pointer into the question's parent domain.
func buildNXDomain(query []byte, soaTTL, minimum uint32) []byte {
	_, q, _ := parseQuestion(query)
	b := append([]byte(nil), query[:q.End]...)
	binary.BigEndian.PutUint16(b[2:], flagQR|flagRD|flagRA|rcodeNXDomain)
	binary.BigEndian.PutUint16(b[6:], 0)
	binary.BigEndian.PutUint16(b[8:], 1)
	binary.BigEndian.PutUint16(b[10:], 0)
	// Owner: pointer to the second label of the question name.
	b = append(b, 0xc0, byte(headerLen+1+query[headerLen]))
	b = u16(b, typeSOA)
	b = u16(b, 1)
	b = u32(b, soaTTL)
	rdata := append([]byte{2, 'n', 's', 0xc0, byte(headerLen + 1 + query[headerLen])}, encName("hostmaster.example")...)
	for _, v := range []uint32{1, 2, 3, 4, minimum} {
		rdata = u32(rdata, v)
	}
	b = u16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

func TestParseQuestionAndNames(t *testing.T) {
	q := buildQuery(0x1234, "WWW.Example.com", typeA, 0)
	h, qq, err := parseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 0x1234 || qq.Name != "WWW.Example.com" || qq.Type != typeA || qq.Class != 1 || qq.End != len(q) {
		t.Fatalf("got %+v %+v", h, qq)
	}
	if _, _, err := parseQuestion(q[:len(q)-1]); err == nil {
		t.Fatal("truncated question parsed")
	}
}

func TestCompressionPointers(t *testing.T) {
	q := buildQuery(1, "a.example.com", typeA, 0)
	r := buildNXDomain(q, 600, 60)
	h, qq, err := parseQuestion(r)
	if err != nil {
		t.Fatal(err)
	}
	rrs, err := parseRecords(r, h, qq.End)
	if err != nil || len(rrs) != 1 {
		t.Fatalf("records %v %v", rrs, err)
	}
	owner, _, err := readName(r, qq.End)
	if err != nil || owner != "example.com" {
		t.Fatalf("owner %q %v", owner, err)
	}
	mname, end, err := readName(r, rrs[0].RDataOff)
	if err != nil || mname != "ns.example.com" || end != rrs[0].RDataOff+5 {
		t.Fatalf("mname %q end %d %v", mname, end, err)
	}

	// Pointer loop must fail, not hang.
	loop := append(make([]byte, headerLen), 0xc0, headerLen)
	if _, _, err := readName(loop, headerLen); err == nil {
		t.Fatal("pointer loop accepted")
	}
	// Pointer past the end.
	if _, _, err := readName([]byte{0xc0, 0xff}, 0); err == nil {
		t.Fatal("out-of-range pointer accepted")
	}
}

func TestCacheTTLDecrement(t *testing.T) {
	c := newCache(4)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	q := buildQuery(1, "example.com", typeA, 0)
	_, qq, _ := parseQuestion(q)
	c.put(qq, "", buildAResponse(q, 300, 120))

	now = now.Add(30 * time.Second)
	q2 := buildQuery(0xbeef, "EXAMPLE.com", typeA, 0)
	_, qq2, _ := parseQuestion(q2)
	got := c.get(q2, qq2, "")
	if got == nil {
		t.Fatal("miss")
	}
	if binary.BigEndian.Uint16(got) != 0xbeef {
		t.Fatal("ID not rewritten")
	}
	if !bytes.Equal(got[headerLen:qq2.End], q2[headerLen:qq2.End]) {
		t.Fatal("question case not echoed")
	}
	h, gq, _ := parseQuestion(got)
	rrs, err := parseRecords(got, h, gq.End)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint16]uint32{typeA: 0, typeOPT: 0}
	var ttls []uint32
	for _, r := range rrs {
		if r.Type == typeA {
			ttls = append(ttls, r.TTL)
		} else if r.Type == typeOPT && r.TTL != want[typeOPT] {
			t.Fatalf("OPT TTL changed to %d", r.TTL)
		}
	}
	if len(ttls) != 2 || ttls[0] != 270 || ttls[1] != 90 {
		t.Fatalf("ttls %v", ttls)
	}

	// Expires at the minimum TTL (120s).
	now = now.Add(90 * time.Second)
	if c.get(q2, qq2, "") != nil {
		t.Fatal("served after expiry")
	}
}

func TestCacheNegativeAndClamps(t *testing.T) {
	c := newCache(4)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	q := buildQuery(1, "nope.example.com", typeA, 0)
	_, qq, _ := parseQuestion(q)
	c.put(qq, "", buildNXDomain(q, 3600, 3600)) // capped to 5 min
	now = now.Add(299 * time.Second)
	if c.get(q, qq, "") == nil {
		t.Fatal("negative answer not cached")
	}
	now = now.Add(2 * time.Second)
	if c.get(q, qq, "") != nil {
		t.Fatal("negative answer cached past 5 min")
	}

	// TTL 0 is held for the 5s minimum.
	q = buildQuery(1, "zero.example.com", typeA, 0)
	_, qq, _ = parseQuestion(q)
	c.put(qq, "", buildAResponse(q, 0))
	now = now.Add(4 * time.Second)
	if c.get(q, qq, "") == nil {
		t.Fatal("ttl 0 not held for 5s")
	}

	// SERVFAIL is not cached.
	q = buildQuery(1, "fail.example.com", typeA, 0)
	_, qq, _ = parseQuestion(q)
	c.put(qq, "", errorResponse(q, rcodeServFail))
	if c.get(q, qq, "") != nil {
		t.Fatal("SERVFAIL cached")
	}
}

func TestCacheLRU(t *testing.T) {
	c := newCache(2)
	names := []string{"a.com", "b.com", "c.com"}
	var qs [][]byte
	for i, n := range names {
		q := buildQuery(1, n, typeA, 0)
		qs = append(qs, q)
		_, qq, _ := parseQuestion(q)
		c.put(qq, "", buildAResponse(q, 60))
		if i == 1 {
			_, qa, _ := parseQuestion(qs[0])
			c.get(qs[0], qa, "") // touch a.com so b.com is evicted
		}
	}
	for i, want := range []bool{true, false, true} {
		_, qq, _ := parseQuestion(qs[i])
		if (c.get(qs[i], qq, "") != nil) != want {
			t.Fatalf("%s present=%v", names[i], !want)
		}
	}
}

func TestTruncation(t *testing.T) {
	q := buildQuery(7, "big.example.com", typeA, 0)
	ttls := make([]uint32, 40) // 40*16 bytes > 512
	big := buildAResponse(q, ttls...)
	if udpLimit(q) != 512 {
		t.Fatal("default limit")
	}
	tr := truncate(big, udpLimit(q))
	h, qq, err := parseQuestion(tr)
	if err != nil || h.Flags&flagTC == 0 || h.ANCount+h.NSCount+h.ARCount != 0 || qq.End != len(tr) {
		t.Fatalf("truncated %+v %v len %d", h, err, len(tr))
	}
	if l := udpLimit(buildQuery(7, "big.example.com", typeA, 600)); l != 600 {
		t.Fatalf("edns limit %d", l)
	}
	// A spoofed query must not get a big UDP reply: the EDNS size is
	// capped and larger answers go over TCP.
	qe := buildQuery(7, "big.example.com", typeA, 65535)
	if udpLimit(qe) != maxUDPSize {
		t.Fatalf("edns limit %d, want %d", udpLimit(qe), maxUDPSize)
	}
	if got := truncate(big, udpLimit(qe)); !bytes.Equal(got, big) {
		t.Fatal("truncated within EDNS limit")
	}
}

// fakeUpstream is a DNS-over-TCP server answering A queries with one
// record. It counts accepted connections and queries.
type fakeUpstream struct {
	ln      net.Listener
	conns   atomic.Int32
	queries atomic.Int32
	delay   time.Duration
	wg      sync.WaitGroup
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{ln: ln}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns.Add(1)
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer c.Close()
				for {
					q, err := readMsg(c, 0xffff)
					if err != nil {
						return
					}
					f.queries.Add(1)
					time.Sleep(f.delay)
					var resp []byte
					if _, qq, _ := parseQuestion(q); strings.HasPrefix(qq.Name, "big") {
						resp = buildAResponse(q, make([]uint32, 40)...)
					} else {
						resp = buildAResponse(q, 60)
					}
					if writeMsg(c, resp) != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); f.wg.Wait() })
	return f
}

type dialRecord struct {
	mu    sync.Mutex
	calls []string
}

func directDial(rec *dialRecord) DialFunc {
	return func(ctx context.Context, src netip.Addr, qname string, dst outbound.Addr) (net.Conn, error) {
		rec.mu.Lock()
		rec.calls = append(rec.calls, src.String()+" "+qname+" "+dst.String())
		rec.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dst.String())
	}
}

func startServer(t *testing.T, s *Server) (addr string) {
	// Pick a port free for TCP, then hope UDP is free too (retry a few).
	for range 10 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = l.Addr().String()
		l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.ListenAndServe(ctx, addr) }()
		select {
		case err := <-done:
			cancel()
			t.Logf("listen %s: %v", addr, err)
			continue
		case <-time.After(50 * time.Millisecond):
		}
		t.Cleanup(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("ListenAndServe: %v", err)
			}
		})
		return addr
	}
	t.Fatal("no free port")
	return ""
}

func udpQuery(t *testing.T, addr string, q []byte) []byte {
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestEndToEnd(t *testing.T) {
	up := newFakeUpstream(t)
	rec := &dialRecord{}
	s := New(Options{
		Dial:     directDial(rec),
		Upstream: up.ln.Addr().String(),
		RouteKey: func(src netip.Addr, qname string, dst netip.Addr) string { return "direct" },
	})
	addr := startServer(t, s)

	// UDP query, then a cache hit with a new ID.
	r := udpQuery(t, addr, buildQuery(0x0101, "Example.COM", typeA, 0))
	h, qq, err := parseQuestion(r)
	if err != nil || h.ID != 0x0101 || h.ANCount != 1 || qq.Name != "Example.COM" {
		t.Fatalf("resp %+v %+v %v", h, qq, err)
	}
	r = udpQuery(t, addr, buildQuery(0x0202, "example.com", typeA, 0))
	if h, _ := parseHeader(r); h.ID != 0x0202 || h.ANCount != 1 {
		t.Fatalf("cached resp %+v", h)
	}
	if up.queries.Load() != 1 {
		t.Fatalf("upstream queries %d, want 1", up.queries.Load())
	}
	rec.mu.Lock()
	if len(rec.calls) != 1 || rec.calls[0] != "127.0.0.1 example.com "+up.ln.Addr().String() {
		t.Fatalf("dial calls %v", rec.calls)
	}
	rec.mu.Unlock()

	// Second miss reuses the pooled upstream connection.
	udpQuery(t, addr, buildQuery(3, "other.com", typeA, 0))
	if up.conns.Load() != 1 || up.queries.Load() != 2 {
		t.Fatalf("conns %d queries %d", up.conns.Load(), up.queries.Load())
	}

	// Oversized answer: truncated on UDP, complete on TCP.
	big := buildQuery(4, "big.example.com", typeA, 0)
	r = udpQuery(t, addr, big)
	if h, _ := parseHeader(r); h.Flags&flagTC == 0 || h.ANCount != 0 {
		t.Fatalf("UDP big not truncated: %+v", h)
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	for _, id := range []uint16{5, 6} { // two queries on one connection
		binary.BigEndian.PutUint16(big, id)
		if err := writeMsg(c, big); err != nil {
			t.Fatal(err)
		}
		r, err = readMsg(c, 0xffff)
		if err != nil {
			t.Fatal(err)
		}
		if h, _ := parseHeader(r); h.ID != id || h.Flags&flagTC != 0 || h.ANCount != 40 {
			t.Fatalf("TCP big: %+v", h)
		}
	}

	s.Flush()
	if s.cache.len() != 0 {
		t.Fatal("flush")
	}
}

func TestUpstreamTimeoutServFail(t *testing.T) {
	up := newFakeUpstream(t)
	up.delay = 500 * time.Millisecond
	s := New(Options{Dial: directDial(&dialRecord{}), Upstream: up.ln.Addr().String(), Timeout: 100 * time.Millisecond})
	addr := startServer(t, s)
	start := time.Now()
	r := udpQuery(t, addr, buildQuery(9, "slow.com", typeA, 0))
	h, _ := parseHeader(r)
	if h.rcode() != rcodeServFail || h.ID != 9 || h.Flags&flagQR == 0 {
		t.Fatalf("got %+v", h)
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Fatal("timeout not honoured")
	}
}

func TestBadUpstreamAndFormErr(t *testing.T) {
	s := New(Options{Dial: directDial(&dialRecord{}), Upstream: ""})
	r := s.handle(context.Background(), netip.Addr{}, buildQuery(1, "x.com", typeA, 0))
	if h, _ := parseHeader(r); h.rcode() != rcodeServFail {
		t.Fatalf("got %+v", h)
	}
	bad := buildQuery(2, "x.com", typeA, 0)
	binary.BigEndian.PutUint16(bad[4:], 2) // QDCOUNT 2
	r = s.handle(context.Background(), netip.Addr{}, bad)
	if h, _ := parseHeader(r); h.rcode() != rcodeFormErr || h.ID != 2 {
		t.Fatalf("got %+v", h)
	}
	for in, want := range map[string]string{"1.1.1.1:53": "1.1.1.1:53", "8.8.8.8": "8.8.8.8:53", "dns.example:5353": "dns.example:5353", "[2606:4700::1111]:53": "[2606:4700::1111]:53"} {
		a, err := parseUpstream(in)
		if err != nil || a.String() != want {
			t.Errorf("parseUpstream(%q) = %v, %v", in, a, err)
		}
	}
}
