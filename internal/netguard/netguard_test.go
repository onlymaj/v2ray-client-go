package netguard

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRefused(t *testing.T) {
	old := SelfAddrs
	SelfAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("172.17.0.1")} }
	ResetCache()
	t.Cleanup(func() { SelfAddrs = old; ResetCache() })
	for _, s := range []string{"127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "255.255.255.255",
		"172.17.0.1", "::ffff:172.17.0.1", "::1", "::", "fe80::1", "::ffff:127.0.0.1"} {
		if !Refused(netip.MustParseAddr(s)) {
			t.Errorf("%s not refused", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "192.168.88.1", "2001:4860::1"} {
		if Refused(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
	if !Refused(netip.Addr{}) {
		t.Error("invalid addr not refused")
	}
}

func TestPrivate(t *testing.T) {
	for _, s := range []string{"10.1.2.3", "172.16.0.1", "192.168.88.1", "100.64.0.1", "100.127.255.254",
		"fd00::1", "::ffff:192.168.1.1"} {
		if !Private(netip.MustParseAddr(s)) {
			t.Errorf("%s not private", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "100.128.0.1", "172.32.0.1", "2001:4860::1"} {
		if Private(netip.MustParseAddr(s)) {
			t.Errorf("%s private", s)
		}
	}
}

func TestParseGateways(t *testing.T) {
	tbl := "Iface\tDestination\tGateway \tFlags\n" +
		"eth0\t00000000\t010011AC\t0003\n" +
		"eth0\t000011AC\t00000000\t0001\n"
	got := ParseGateways(strings.NewReader(tbl))
	if len(got) != 1 || got[0] != netip.MustParseAddr("172.17.0.1") {
		t.Fatalf("got %v", got)
	}
}

// Self must match only exact own/gateway addresses, never whole ranges a LAN
// device could use (round-5 finding: 169.254.x.x got the gateway's DNS budget).
func TestSelfIsExact(t *testing.T) {
	gw := netip.MustParseAddr("172.17.0.1")
	old := SelfAddrs
	SelfAddrs = func() []netip.Addr { return []netip.Addr{gw, netip.MustParseAddr("172.17.0.2")} }
	ResetCache()
	defer func() { SelfAddrs = old; ResetCache() }()
	if !Self(gw) || !Self(netip.MustParseAddr("::ffff:172.17.0.1")) {
		t.Fatal("gateway not recognised")
	}
	for _, s := range []string{"169.254.7.7", "127.0.0.1", "172.17.0.3", "192.168.88.10"} {
		if Self(netip.MustParseAddr(s)) {
			t.Errorf("Self(%s) = true", s)
		}
	}
	if !Refused(netip.MustParseAddr("169.254.7.7")) {
		t.Error("Refused must still cover link-local")
	}
}

// Round 9: an IPv6 literal with a zone ("fd00::2%x", accepted by SOCKS5 and
// HTTP CONNECT) equals no map key, so the container's own address written
// that way was not refused.
func TestZonedSelfAddressRefused(t *testing.T) {
	orig := SelfAddrs
	SelfAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("fd00::2")} }
	ResetCache()
	defer func() { SelfAddrs = orig; ResetCache() }()
	for _, a := range []string{"fd00::2", "fd00::2%eth0", "fd00::2%x"} {
		if ip := netip.MustParseAddr(a); !Self(ip) || !Refused(ip) {
			t.Errorf("%s not refused", a)
		}
	}
	if Refused(netip.MustParseAddr("fd00::3%eth0")) {
		t.Error("foreign address refused")
	}
}
