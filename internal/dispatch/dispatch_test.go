package dispatch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"github.com/onlymaj/v2ray-client-go/internal/transport"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/router"
)

// The fake "vless" protocol ignores the transport and connects to a local
// echo server that first writes "<dest>\n", then echoes until EOF and
// half-closes.
var echoAddr string

func init() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	echoAddr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				dest, _ := r.ReadString('\n')
				c.Write([]byte(dest))
				io.Copy(c, r)
				c.(*net.TCPConn).CloseWrite()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	outbound.Register("vless", func(_ []byte, _ func(ctx context.Context) (net.Conn, error)) (outbound.Dialer, error) {
		return fakeProto{}, nil
	})
}

type fakeProto struct{}

// lastSource is the transport.Source of the latest fakeProto dial.
var lastSource atomic.Value

func (fakeProto) Dial(ctx context.Context, _ string, dest outbound.Addr) (net.Conn, error) {
	lastSource.Store(transport.Source(ctx))
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		return nil, err
	}
	c.Write([]byte(dest.String() + "\n"))
	return c, nil
}

func cli(id string, enabled bool) config.Client {
	return config.Client{ID: id, Enabled: enabled, Protocol: "vless", Address: "127.0.0.1", Port: 1,
		UUID: "11111111-2222-3333-4444-555555555555", Network: "tcp", TLS: "none"}
}

func testConfig() *config.Config {
	return &config.Config{
		Clients: []config.Client{cli("a", true), cli("b", true), cli("c", false)},
		Groups: []group.Group{
			{ID: "g1", Strategy: group.Failover, Members: []string{"a", "b"}},
			{ID: "g2", Strategy: group.Failover, Members: []string{"c"}},
			{ID: "empty", Strategy: group.Failover, Members: []string{}},
		},
		Rules: []router.Rule{
			{ID: "r-src", Type: "source", Values: []string{"10.0.0.5"}, Target: router.Target{Kind: router.KindClient, ID: "c"}},
			{ID: "r-direct", Type: "domain", Values: []string{"direct.test"}, Target: router.Target{Kind: router.KindDirect}},
			{ID: "r-block", Type: "domain", Values: []string{"block.test"}, Target: router.Target{Kind: router.KindBlock}},
			{ID: "r-a", Type: "dest", Values: []string{"1.2.3.4"}, Target: router.Target{Kind: router.KindClient, ID: "a"}},
			{ID: "r-g2", Type: "domain", Values: []string{"g2.test"}, Target: router.Target{Kind: router.KindGroup, ID: "g2"}},
			{ID: "r-empty", Type: "domain", Values: []string{"empty.test"}, Target: router.Target{Kind: router.KindGroup, ID: "empty"}},
			{ID: "r-unknown", Type: "domain", Values: []string{"unknown.test"}, Target: router.Target{Kind: router.KindClient, ID: "zz"}},
			{ID: "default", Type: "default", Target: router.Target{Kind: router.KindGroup, ID: "g1"}},
		},
		Settings: config.Settings{KillSwitch: config.KillSwitchBlock},
	}
}

var (
	lan   = netip.MustParseAddr("192.168.1.10")
	other = netip.MustParseAddr("8.8.8.8")
)

func TestRoute(t *testing.T) {
	d, err := New(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var changes []string
	d.OnGroupChange(func(g, cur string) { changes = append(changes, g+"="+cur) })

	check := func(name string, src netip.Addr, domain string, dst netip.Addr, want Decision) {
		t.Helper()
		if got := d.Route(src, domain, dst); got != want {
			t.Errorf("%s: got %+v, want %+v", name, got, want)
		}
	}
	check("no health -> kill block", lan, "", other, Decision{RuleID: "default", Kind: KindBlock, GroupID: "g1", KillSwitch: true})
	d.HealthUpdate("a", true, 50*time.Millisecond)
	d.HealthUpdate("c", true, 10*time.Millisecond)
	check("group", lan, "", other, Decision{RuleID: "default", Kind: KindClient, ClientID: "a", GroupID: "g1"})
	check("client", lan, "", netip.MustParseAddr("1.2.3.4"), Decision{RuleID: "r-a", Kind: KindClient, ClientID: "a"})
	check("direct", lan, "direct.test", other, Decision{RuleID: "r-direct", Kind: KindDirect})
	check("block", lan, "block.test", other, Decision{RuleID: "r-block", Kind: KindBlock})
	check("disabled client", netip.MustParseAddr("10.0.0.5"), "", other, Decision{RuleID: "r-src", Kind: KindBlock, KillSwitch: true})
	check("disabled group member", lan, "g2.test", other, Decision{RuleID: "r-g2", Kind: KindBlock, GroupID: "g2", KillSwitch: true})
	check("empty group", lan, "empty.test", other, Decision{RuleID: "r-empty", Kind: KindBlock, GroupID: "empty", KillSwitch: true})
	check("unknown client", lan, "unknown.test", other, Decision{RuleID: "r-unknown", Kind: KindBlock, KillSwitch: true})
	if len(changes) != 1 || changes[0] != "g1=a" {
		t.Errorf("changes = %v", changes)
	}

	// Kill switch direct; enable c; groups and their state survive.
	cfg := testConfig()
	cfg.Settings.KillSwitch = config.KillSwitchDirect
	cfg.Clients[2].Enabled = true
	clientA := d.Client("a")
	if err := d.Update(cfg); err != nil {
		t.Fatal(err)
	}
	if d.Client("a") != clientA {
		t.Error("unchanged client was rebuilt")
	}
	if d.GroupCurrent("g1") != "a" {
		t.Error("group state lost on update")
	}
	// A result from before c was disabled does not count (round 15): the
	// group waits for c's first check.
	check("enabled c, not checked yet", lan, "g2.test", other, Decision{RuleID: "r-g2", Kind: KindBlock, GroupID: "g2", KillSwitch: true})
	d.HealthUpdate("c", true, 30*time.Millisecond)
	check("enabled c via group", lan, "g2.test", other, Decision{RuleID: "r-g2", Kind: KindClient, ClientID: "c", GroupID: "g2"})
	check("kill direct", lan, "unknown.test", other, Decision{RuleID: "r-unknown", Kind: KindDirect, KillSwitch: true})

	// a goes down: failover to b once b is up.
	d.HealthUpdate("b", true, 30*time.Millisecond)
	d.HealthUpdate("a", false, 0)
	check("failover", lan, "", other, Decision{RuleID: "default", Kind: KindClient, ClientID: "b", GroupID: "g1"})

	// Changing a client rebuilds it; changing a group re-feeds health.
	cfg = testConfig()
	cfg.Clients[0].Port = 2
	cfg.Groups[0].Members = []string{"b", "a"}
	if err := d.Update(cfg); err != nil {
		t.Fatal(err)
	}
	if d.Client("a") == clientA {
		t.Error("changed client not rebuilt")
	}
	check("regrouped", lan, "", other, Decision{RuleID: "default", Kind: KindClient, ClientID: "b", GroupID: "g1"})
	// Disabling b in place: unchanged group must drop it.
	cfg = testConfig()
	cfg.Clients[0].Port = 2
	cfg.Groups[0].Members = []string{"b", "a"}
	cfg.Clients[1].Enabled = false
	d.Update(cfg)
	check("b disabled", lan, "", other, Decision{RuleID: "default", Kind: KindBlock, GroupID: "g1", KillSwitch: true})
}

func TestBadRulesKeepState(t *testing.T) {
	d, _ := New(testConfig(), nil)
	defer d.Close()
	cfg := testConfig()
	cfg.Rules = append(cfg.Rules, router.Rule{ID: "x", Type: "bogus"})
	if err := d.Update(cfg); err == nil {
		t.Fatal("want error")
	}
	if got := d.Route(lan, "direct.test", other); got.Kind != KindDirect {
		t.Fatalf("old rules lost: %+v", got)
	}
}

type fakeTracker struct {
	mu   sync.Mutex
	open []*fakeTracked
}

type fakeTracked struct {
	src                            netip.AddrPort
	dst, domain, rule, client, grp string
	up, down                       atomic.Int64
	closed                         atomic.Bool
}

func (t *fakeTracker) Open(src netip.AddrPort, dst, domain, ruleID, clientID, groupID string) Tracked {
	tr := &fakeTracked{src: src, dst: dst, domain: domain, rule: ruleID, client: clientID, grp: groupID}
	t.mu.Lock()
	t.open = append(t.open, tr)
	t.mu.Unlock()
	return tr
}
func (t *fakeTracked) AddUp(n int64)   { t.up.Add(n) }
func (t *fakeTracked) AddDown(n int64) { t.down.Add(n) }
func (t *fakeTracked) Close()          { t.closed.Store(true) }

// tcpPair returns two connected loopback TCP conns.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn)
	go func() { c, _ := ln.Accept(); ch <- c }()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a.(*net.TCPConn), (<-ch).(*net.TCPConn)
}

// run starts Handle on one end and returns the user end and the tracker.
func run(t *testing.T, d *Dispatcher, tr *fakeTracker, dst outbound.Addr, sniffable bool) (*net.TCPConn, chan struct{}) {
	user, in := tcpPair(t)
	done := make(chan struct{})
	go func() {
		d.Handle(in, netip.MustParseAddrPort("192.168.1.10:5555"), dst, sniffable)
		close(done)
	}()
	return user, done
}

func newHandleDispatcher(t *testing.T) (*Dispatcher, *fakeTracker) {
	tr := &fakeTracker{}
	d, err := New(testConfig(), tr)
	if err != nil {
		t.Fatal(err)
	}
	d.HealthUpdate("a", true, time.Millisecond)
	t.Cleanup(d.Close)
	return d, tr
}

func TestHandleHTTPSniffHalfClose(t *testing.T) {
	d, tr := newHandleDispatcher(t)
	user, done := run(t, d, tr, outbound.Addr{IP: other, Port: 80}, true)
	defer user.Close()
	req := "GET / HTTP/1.1\r\nHost: Web.Test:80\r\n\r\n"
	user.Write([]byte(req))
	user.CloseWrite()
	got, err := io.ReadAll(user)
	if err != nil {
		t.Fatal(err)
	}
	if want := "web.test:80\n" + req; string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	<-done
	o := tr.open[0]
	if o.domain != "web.test" || o.client != "a" || o.grp != "g1" || o.dst != "8.8.8.8:80" || !o.closed.Load() {
		t.Fatalf("tracked %+v", o)
	}
	if o.up.Load() != int64(len(req)) || o.down.Load() != int64(len(got)) {
		t.Fatalf("up=%d down=%d", o.up.Load(), o.down.Load())
	}
}

func clientHello(t *testing.T, sni string) []byte {
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: sni}).Handshake()
	defer a.Close()
	defer b.Close()
	buf := make([]byte, 5)
	io.ReadFull(b, buf)
	rec := make([]byte, int(buf[3])<<8|int(buf[4]))
	io.ReadFull(b, rec)
	return append(buf, rec...)
}

func TestHandleTLSReplay(t *testing.T) {
	d, tr := newHandleDispatcher(t)
	user, done := run(t, d, tr, outbound.Addr{IP: other, Port: 443}, true)
	defer user.Close()
	hello := clientHello(t, "sni.test")
	// Write in two parts to exercise ErrNeedMore.
	user.Write(hello[:10])
	time.Sleep(20 * time.Millisecond)
	user.Write(hello[10:])
	user.CloseWrite()
	got, _ := io.ReadAll(user)
	if want := "sni.test:443\n" + string(hello); string(got) != want {
		t.Fatalf("replay mismatch: got %d bytes, want %d", len(got), len(want))
	}
	<-done
}

func TestHandleServerFirst(t *testing.T) {
	old := sniffTimeout
	sniffTimeout = 30 * time.Millisecond
	defer func() { sniffTimeout = old }()
	d, tr := newHandleDispatcher(t)
	user, done := run(t, d, tr, outbound.Addr{IP: other, Port: 22}, true)
	defer user.Close()
	line, err := bufio.NewReader(user).ReadString('\n')
	if err != nil || line != "8.8.8.8:22\n" {
		t.Fatalf("got %q %v", line, err)
	}
	user.Close()
	<-done
}

func TestHandleKnownDomainNoSniff(t *testing.T) {
	d, tr := newHandleDispatcher(t)
	user, done := run(t, d, tr, outbound.Addr{Domain: "known.test", Port: 443}, false)
	defer user.Close()
	user.CloseWrite()
	got, _ := io.ReadAll(user)
	if string(got) != "known.test:443\n" {
		t.Fatalf("got %q", got)
	}
	<-done
	if tr.open[0].domain != "known.test" {
		t.Fatal("domain not tracked")
	}
}

func TestHandleBlock(t *testing.T) {
	d, tr := newHandleDispatcher(t)
	user, done := run(t, d, tr, outbound.Addr{Domain: "block.test", Port: 443}, false)
	defer user.Close()
	user.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := user.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("blocked conn not closed: %d %v", n, err)
	}
	<-done
	if !tr.open[0].closed.Load() {
		t.Fatal("tracked not closed")
	}
}

func TestIdleTimeout(t *testing.T) {
	old := idleTimeout
	idleTimeout = 50 * time.Millisecond
	defer func() { idleTimeout = old }()
	d, tr := newHandleDispatcher(t)
	user, done := run(t, d, tr, outbound.Addr{Domain: "idle.test", Port: 1}, false)
	defer user.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle conn not closed")
	}
}

func TestDialDirect(t *testing.T) {
	d, _ := newHandleDispatcher(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, dec, err := d.Dial(context.Background(), lan, "direct.test",
		outbound.Addr{IP: netip.MustParseAddr("127.0.0.1"), Port: port})
	if err != nil || dec.Kind != KindDirect {
		t.Fatalf("%v %+v", err, dec)
	}
	c.Close()
	if _, _, err := d.Dial(context.Background(), lan, "", outbound.Addr{Domain: "block.test", Port: 1}); err != ErrBlocked {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
}

type chunkConn struct {
	net.Conn
	sizes []int // what each Read is asked to fill
	data  [][]byte
}

func (c *chunkConn) Read(p []byte) (int, error) {
	c.sizes = append(c.sizes, len(p))
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data[0])
	if c.data[0] = c.data[0][n:]; len(c.data[0]) == 0 {
		c.data = c.data[1:]
	}
	return n, nil
}

// Round 20: each direction of a relay held a 16 KiB buffer while it waited
// for data, 32 KiB per idle connection. It waits with a small one and
// takes the large one only while data flows. Round 21: the first version
// kept the large one after any read of 2 KiB or more, which is after
// almost every burst; the cases are the bursts that showed it. (A burst
// whose last read is nearly a whole large buffer, or exactly the small
// one, still waits with the large one.)
func TestRelayWaitsWithASmallBuffer(t *testing.T) {
	for _, burst := range [][]int{{100}, {1500}, {4096}, {6000}, {16384, 3000}, {16384, 16384, 9000}, {1000, 1000, 5000}, {100, 40000, 100}} {
		a, b := net.Pipe()
		var got bytes.Buffer
		done := make(chan struct{})
		go func() { io.Copy(&got, b); close(done) }()
		p1, p2 := net.Pipe()
		src := &chunkConn{Conn: p1}
		want := 0
		for _, n := range burst {
			src.data = append(src.data, make([]byte, n))
			want += n
		}
		w := newWatch(src, a, true)
		total := int64(0)
		copyHalf(a, src, w, func(n int64) { total += n })
		w.stop()
		a.Close()
		<-done
		b.Close()
		p1.Close()
		p2.Close()
		if total != int64(want) || got.Len() != want {
			t.Fatalf("%v: copied %d, received %d", burst, total, got.Len())
		}
		// The last read is the one that would wait for more.
		if n := src.sizes[len(src.sizes)-1]; n != idleBuf || src.sizes[0] != idleBuf {
			t.Errorf("%v: read sizes %v: the reads that wait must use the small buffer", burst, src.sizes)
		}
		if big := slices.Max(src.sizes) > idleBuf; big != (want >= idleBuf) {
			t.Errorf("%v: read sizes %v: large buffer used %v", burst, src.sizes, big)
		}
	}
}
