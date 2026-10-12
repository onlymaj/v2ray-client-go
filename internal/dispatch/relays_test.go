package dispatch

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/client"
	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// register adds a fake established relay for (src, domain, dst) routed as
// the dispatcher currently would, and returns a func reporting whether the
// relay was cut.
func register(t *testing.T, d *Dispatcher, domain string, dst netip.Addr) (Decision, func() bool) {
	t.Helper()
	dec := d.Route(lan, domain, dst)
	inA, inB := net.Pipe()
	outA, outB := net.Pipe()
	t.Cleanup(func() { inA.Close(); inB.Close(); outA.Close(); outB.Close() })
	d.relays.add(&activeRelay{src: lan, domain: domain, dstIP: dst, dec: dec, cli: d.Client(dec.ClientID), in: inA, out: outA})
	return dec, func() bool {
		inB.SetReadDeadline(time.Now().Add(300 * time.Millisecond)) // cut() closes in the background
		_, err := inB.Read(make([]byte, 1))
		return err != nil && !isTimeout(err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func killSwitchConfig(mode string) *config.Config {
	c := testConfig()
	c.Settings.KillSwitch = mode
	return c
}

// Regression (round 6): a relay that went direct through the kill switch
// must be cut when the kill switch becomes "block".
func TestRelayCutWhenKillSwitchBlocks(t *testing.T) {
	d, err := New(killSwitchConfig(config.KillSwitchDirect), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	dec, cut := register(t, d, "empty.test", other)
	if dec.Kind != KindDirect || !dec.KillSwitch {
		t.Fatalf("setup decision %+v", dec)
	}
	if cut() {
		t.Fatal("relay cut before any change")
	}
	if err := d.Update(killSwitchConfig(config.KillSwitchBlock)); err != nil {
		t.Fatal(err)
	}
	if !cut() {
		t.Fatal("kill-switch direct relay survived the switch to block")
	}
}

// Regression (round 6): when a proxy recovers, relays that went direct only
// because no proxy was healthy must be cut so they reconnect via the proxy.
func TestRelayCutWhenProxyRecovers(t *testing.T) {
	d, err := New(killSwitchConfig(config.KillSwitchDirect), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.HealthUpdate("a", false, 0) // both checked and down (an unchecked member would block, rounds 13 and 14)
	d.HealthUpdate("b", false, 0)
	dec, cut := register(t, d, "any.test", other) // default rule -> group g1, nobody up
	if dec.Kind != KindDirect || !dec.KillSwitch {
		t.Fatalf("setup decision %+v", dec)
	}
	d.HealthUpdate("a", true, time.Millisecond)
	if !cut() {
		t.Fatal("kill-switch direct relay survived the proxy recovering")
	}
}

// A relay on a working proxy route is not disturbed by an unrelated config
// save or by another member's health changing.
func TestRelayKeptWhenRouteUnchanged(t *testing.T) {
	d, err := New(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.HealthUpdate("a", true, time.Millisecond)
	dec, cut := register(t, d, "", netip.MustParseAddr("1.2.3.4")) // rule r-a -> client a
	if dec.Kind != KindClient || dec.ClientID != "a" {
		t.Fatalf("setup decision %+v", dec)
	}
	if err := d.Update(testConfig()); err != nil {
		t.Fatal(err)
	}
	d.HealthUpdate("b", true, time.Millisecond)
	if cut() {
		t.Fatal("unchanged relay was cut")
	}
}

// Regression (round 7): editing a client (same ID, new server) must cut
// relays on the old server, and so must removing a member from its group.
func TestRelayCutWhenClientEditedOrRemovedFromGroup(t *testing.T) {
	d, err := New(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.HealthUpdate("a", true, time.Millisecond)
	_, cutDirectRule := register(t, d, "", netip.MustParseAddr("1.2.3.4")) // rule r-a -> client a
	_, cutGroup := register(t, d, "any.test", other)                       // default -> group g1 -> a

	edited := testConfig()
	edited.Clients[0].Address = "127.0.0.2" // client a moves to another server
	if err := d.Update(edited); err != nil {
		t.Fatal(err)
	}
	if !cutDirectRule() {
		t.Fatal("relay to the edited client's old server survived")
	}
	if !cutGroup() {
		t.Fatal("group relay on the edited client survived")
	}

	d.HealthUpdate("a", true, time.Millisecond)
	_, cutGroup2 := register(t, d, "any.test", other)
	removed := testConfig()
	removed.Clients[0].Address = "127.0.0.2"
	removed.Groups[0].Members = []string{"b"} // a leaves g1 but stays enabled
	if err := d.Update(removed); err != nil {
		t.Fatal(err)
	}
	if !cutGroup2() {
		t.Fatal("relay through a client removed from its group survived")
	}
}

// Regression (round 8): re-checking a relay's route (after registering it,
// and on every config save or health result) took a round-robin turn, so
// with two members every connection landed on the same one.
func TestRecheckLeavesRoundRobinAlone(t *testing.T) {
	cfg := testConfig()
	cfg.Groups[0].Strategy = group.RoundRobin // g1: a, b; the default route
	tr := &fakeTracker{}
	d, err := New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.HealthUpdate("a", true, time.Millisecond)
	d.HealthUpdate("b", true, time.Millisecond)
	for range 6 {
		user, done := run(t, d, tr, outbound.Addr{IP: other, Port: 80}, false)
		user.CloseWrite()
		io.Copy(io.Discard, user)
		user.Close()
		<-done
		d.recheck(false) // as a config save would
	}
	var got string
	for _, o := range tr.open {
		got += o.client
	}
	if got != "ababab" {
		t.Fatalf("round-robin picked %q, want ababab", got)
	}
	if d.Preview(lan, "", other).ClientID != "a" || d.Preview(lan, "", other).ClientID != "a" {
		t.Fatal("Preview moved the round-robin on")
	}
}

// Regression (round 8): closing a replaced gRPC client waits for a dial in
// progress (up to the dial timeout with a dead server). Update must not
// wait for it while holding the dispatcher lock.
func TestUpdateDoesNotWaitForClientClose(t *testing.T) {
	block := make(chan struct{})
	orig := closeClient
	closeClient = func(*client.Client) { <-block }
	defer func() { close(block); closeClient = orig }()
	d, err := New(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Clients[0].Port = 2 // rebuilt: the old client is closed
	done := make(chan struct{})
	go func() {
		d.Update(cfg)
		d.HealthUpdate("a", true, time.Millisecond) // needs the dispatcher lock
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Update blocked on closing the replaced client")
	}
}
