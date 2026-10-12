package dispatch

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/netguard"
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
	old := netguard.SelfAddrs
	netguard.SelfAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("172.17.0.1")} }
	netguard.ResetCache()
	defer func() {
		netguard.SelfAddrs = old
		netguard.ResetCache()
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

// Flipping AllowPrivateServers, or a client's SubscriptionID, rebuilds the
// client so its server dial guard matches; other updates keep it.
func TestUpdateRebuildsOnPrivatePolicy(t *testing.T) {
	cfg := testConfig()
	d, err := New(cfg, &fakeTracker{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	a := d.Client("a")
	if a == nil {
		t.Fatal("client a not built")
	}
	if err := d.Update(cfg); err != nil {
		t.Fatal(err)
	}
	if d.Client("a") != a {
		t.Fatal("unchanged update rebuilt the client")
	}
	cfg.Settings.AllowPrivateServers = true
	if err := d.Update(cfg); err != nil {
		t.Fatal(err)
	}
	b := d.Client("a")
	if b == a {
		t.Fatal("AllowPrivateServers flip did not rebuild the client")
	}
	cfg.Clients[0].SubscriptionID = "s1"
	if err := d.Update(cfg); err != nil {
		t.Fatal(err)
	}
	if d.Client("a") == b {
		t.Fatal("SubscriptionID change did not rebuild the client")
	}
}

// Round 12: the relay watchdog compared wall-clock times, so a clock step
// (the router has no battery clock) cut every quiet relay or held the idle
// limits off. It now measures from a monotonic base.
func TestWatchUsesMonotonicClock(t *testing.T) {
	if n := monoNow(); n < 0 || n > int64(24*time.Hour) {
		t.Fatalf("monoNow = %d: looks like wall-clock time", n)
	}
	var w watch
	w.touch()
	if got := w.last.Load(); got > int64(24*time.Hour) {
		t.Fatalf("touch stored %d: wall-clock time", got)
	}
}

// Round 13: a group whose members had not been checked yet counted as down.
// With the kill switch in direct mode, every start sent group-routed traffic
// and DNS out in the clear for the first seconds, although the proxies were
// fine. Until the first health result the group blocks instead.
func TestKillSwitchDirectBlocksBeforeFirstCheck(t *testing.T) {
	cfg := testConfig()
	cfg.Settings.KillSwitch = config.KillSwitchDirect
	d, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got := d.Route(lan, "", other); got.Kind != KindBlock || !got.KillSwitch {
		t.Fatalf("before any health result: %+v, want a block", got)
	}
	// Round 14: one dead member reporting first, or a disabled member in
	// the group, made the group count as checked while a healthy member
	// had not been tried yet.
	d.HealthUpdate("a", false, 0)
	if got := d.Route(lan, "", other); got.Kind != KindBlock || !got.KillSwitch {
		t.Fatalf("a down, b not checked yet: %+v, want a block", got)
	}
	d.HealthUpdate("b", false, 0)
	if got := d.Route(lan, "", other); got.Kind != KindDirect || !got.KillSwitch {
		t.Fatalf("all members checked and down: %+v, want direct", got)
	}
	d.HealthUpdate("b", true, time.Millisecond)
	if got := d.Route(lan, "", other); got.Kind != KindClient || got.ClientID != "b" {
		t.Fatalf("member up: %+v", got)
	}
}

// Round 14: a disabled member counted as "checked", so a group of one
// enabled client and one disabled client went direct at every start.
func TestUncheckedGroupWithDisabledMemberBlocks(t *testing.T) {
	cfg := testConfig()
	cfg.Settings.KillSwitch = config.KillSwitchDirect
	cfg.Groups[0].Members = []string{"a", "c"} // c is disabled
	d, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got := d.Route(lan, "", other); got.Kind != KindBlock || !got.KillSwitch {
		t.Fatalf("a not checked yet, c disabled: %+v, want a block", got)
	}
	d.HealthUpdate("a", false, 0)
	if got := d.Route(lan, "", other); got.Kind != KindDirect || !got.KillSwitch {
		t.Fatalf("a checked and down: %+v, want direct", got)
	}
}
