package dispatch

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
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
	d.relays.add(&activeRelay{src: lan, domain: domain, dstIP: dst, dec: dec, in: inA, out: outA})
	return dec, func() bool {
		inB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
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
	dec, cut := register(t, d, "any.test", other) // default rule -> group g1, nobody up yet
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
