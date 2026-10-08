package dispatch

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/router"
)

func stubLookup(t *testing.T, ip string) {
	old := lookupIP
	lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(ip)}, nil
	}
	t.Cleanup(func() { lookupIP = old })
}

func expectClosed(t *testing.T, d *Dispatcher, tr *fakeTracker, dst outbound.Addr, rule string) {
	t.Helper()
	user, done := run(t, d, tr, dst, false)
	defer user.Close()
	user.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := user.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("%v: conn not closed", dst)
	}
	<-done
	if got := tr.open[len(tr.open)-1].rule; got != rule {
		t.Fatalf("%v: rule %q, want %q", dst, got, rule)
	}
}

func TestHandleRefusesLocal(t *testing.T) {
	old := selfAddrs
	selfAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("172.17.0.1")} }
	selfMu.Lock()
	selfSet = nil
	selfMu.Unlock()
	defer func() {
		selfAddrs = old
		selfMu.Lock()
		selfSet = nil
		selfMu.Unlock()
	}()
	d, tr := newHandleDispatcher(t)
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "172.17.0.1", "::1"} {
		expectClosed(t, d, tr, outbound.Addr{IP: netip.MustParseAddr(ip), Port: 443}, "refused")
	}
	// A domain routed direct that resolves to the router is refused too.
	stubLookup(t, "172.17.0.1")
	expectClosed(t, d, tr, outbound.Addr{Domain: "direct.test", Port: 443}, "refused")
}

// A domain routed direct is resolved and dest rules apply to the result.
func TestHandleDirectDomainDestRule(t *testing.T) {
	d, tr := newHandleDispatcher(t)
	cfg := testConfig()
	cfg.Rules = append([]router.Rule{{ID: "r-dblock", Type: "dest", Values: []string{"203.0.113.0/24"},
		Target: router.Target{Kind: router.KindBlock}}}, cfg.Rules...)
	if err := d.Update(cfg); err != nil {
		t.Fatal(err)
	}
	stubLookup(t, "203.0.113.7")
	expectClosed(t, d, tr, outbound.Addr{Domain: "direct.test", Port: 443}, "r-dblock")
}

// A client that never sends is dropped after silentTimeout.
func TestSilentTimeout(t *testing.T) {
	old := silentTimeout
	silentTimeout = 50 * time.Millisecond
	defer func() { silentTimeout = old }()
	d, tr := newHandleDispatcher(t)
	user, done := run(t, d, tr, outbound.Addr{Domain: "idle.test", Port: 1}, false)
	defer user.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("silent conn not closed")
	}
}

// Once the client sends, the normal idle limit applies.
func TestSilentTimeoutLifted(t *testing.T) {
	old := silentTimeout
	silentTimeout = 100 * time.Millisecond
	defer func() { silentTimeout = old }()
	d, tr := newHandleDispatcher(t)
	user, done := run(t, d, tr, outbound.Addr{Domain: "talk.test", Port: 1}, false)
	defer user.Close()
	user.Write([]byte("x"))
	select {
	case <-done:
		t.Fatal("active conn closed by silent timeout")
	case <-time.After(300 * time.Millisecond):
	}
	user.CloseWrite()
	io.ReadAll(user)
	<-done
}

func TestParseGateways(t *testing.T) {
	tbl := "Iface\tDestination\tGateway \tFlags\n" +
		"eth0\t00000000\t010011AC\t0003\n" +
		"eth0\t000011AC\t00000000\t0001\n"
	got := parseGateways(strings.NewReader(tbl))
	if len(got) != 1 || got[0] != netip.MustParseAddr("172.17.0.1") {
		t.Fatalf("got %v", got)
	}
}
