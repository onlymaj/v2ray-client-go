package router

import (
	"net/netip"
	"testing"
)

var testRules = []Rule{
	{ID: "lan", Type: "dest", Values: []string{"192.168.0.0/16", "fd00::/8"}, Target: Target{Kind: KindDirect}},
	{ID: "kid", Type: "source", Values: []string{"192.168.88.50", "2001:db8:1::/48"}, Target: Target{Kind: KindClient, ID: "c2"}},
	{ID: "ir", Type: "domain", Values: []string{"*.ir", "Digikala.com."}, Target: Target{Kind: KindDirect}},
	{ID: "ads", Type: "domain", Values: []string{"*.doubleclick.net"}, Target: Target{Kind: KindBlock}},
	{ID: "ip", Type: "dest", Values: []string{"1.1.1.1"}, Target: Target{Kind: KindClient, ID: "c3"}},
	{ID: "def", Type: "default", Target: Target{Kind: KindGroup, ID: "main"}},
	{ID: "dead", Type: "dest", Values: []string{"9.9.9.9"}, Target: Target{Kind: KindDirect}},
}

// Round 8: the UI greys out rules below the default rule and says they
// never match, but the engine still matched them, so a "direct" rule the
// admin believed dead kept sending traffic around the proxy.
func TestRulesAfterDefaultNeverMatch(t *testing.T) {
	e, err := Compile(testRules)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.Match(netip.MustParseAddr("10.0.0.2"), "", netip.MustParseAddr("9.9.9.9")); r == nil || r.ID != "def" {
		t.Fatalf("rule below the default matched: %+v", r)
	}
	bad := append(append([]Rule(nil), testRules...), Rule{ID: "x", Type: "dest", Values: []string{"nope"}, Target: Target{Kind: KindDirect}})
	if _, err := Compile(bad); err == nil {
		t.Fatal("invalid rule below the default was not checked")
	}
}

func TestMatch(t *testing.T) {
	e, err := Compile(testRules)
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr
	var none netip.Addr
	tests := []struct {
		src    netip.Addr
		domain string
		dst    netip.Addr
		want   string
	}{
		{a("192.168.88.10"), "", a("192.168.1.1"), "lan"},
		{a("192.168.88.50"), "", a("192.168.1.1"), "lan"}, // order: lan before kid
		{a("192.168.88.50"), "google.com", a("8.8.8.8"), "kid"},
		{a("::ffff:192.168.88.50"), "", a("8.8.8.8"), "kid"}, // v4-mapped
		{a("2001:db8:1:5::9"), "", a("2a00::1"), "kid"},
		{a("2001:db8:2::9"), "", a("fd12::1"), "lan"},
		{a("10.0.0.2"), "www.Shaparak.IR.", a("8.8.8.8"), "ir"},
		{a("10.0.0.2"), "ir", a("8.8.8.8"), "def"}, // *.ir is subdomains only
		{a("10.0.0.2"), "digikala.com", none, "ir"},
		// Round 8: a plain value also matches its subdomains, as the UI and
		// API promise. It used to match exactly, so "example.com -> block"
		// let www.example.com through to the default rule.
		{a("10.0.0.2"), "www.digikala.com", none, "ir"},
		{a("10.0.0.2"), "a.b.digikala.com", none, "ir"},
		{a("10.0.0.2"), "notdigikala.com", none, "def"},
		{a("10.0.0.2"), "notdoubleclick.net", none, "def"},
		{a("10.0.0.2"), "a.b.doubleclick.net", none, "ads"},
		{a("10.0.0.2"), "", a("1.1.1.1"), "ip"},
		{a("10.0.0.2"), "", a("1.1.1.2"), "def"},
		{none, "", none, "def"},
	}
	for _, tt := range tests {
		r := e.Match(tt.src, tt.domain, tt.dst)
		if r == nil || r.ID != tt.want {
			t.Errorf("Match(%v, %q, %v) = %v, want %s", tt.src, tt.domain, tt.dst, r, tt.want)
		}
	}
}

func TestNoDefault(t *testing.T) {
	e, err := Compile(testRules[1:2])
	if err != nil {
		t.Fatal(err)
	}
	if r := e.Match(netip.Addr{}, "x.com", netip.MustParseAddr("8.8.8.8")); r != nil {
		t.Errorf("got %v, want nil", r)
	}
}

func TestCompileErrors(t *testing.T) {
	bad := [][]Rule{
		{{ID: "a", Type: "dest", Values: []string{"300.1.1.1/8"}, Target: Target{Kind: KindDirect}}},
		{{ID: "a", Type: "domain", Values: []string{"*."}, Target: Target{Kind: KindDirect}}},
		{{ID: "a", Type: "domain", Values: []string{"a.*.com"}, Target: Target{Kind: KindDirect}}},
		{{ID: "a", Type: "port", Target: Target{Kind: KindDirect}}},
		{{ID: "a", Type: "dest", Values: []string{"1.1.1.1"}, Target: Target{Kind: KindClient}}},
		{{ID: "a", Type: "dest", Values: []string{"1.1.1.1"}, Target: Target{Kind: "proxy"}}},
		{{ID: "a", Type: "default", Target: Target{Kind: KindDirect}}, {ID: "b", Type: "default", Target: Target{Kind: KindDirect}}},
	}
	for i, rules := range bad {
		if _, err := Compile(rules); err == nil {
			t.Errorf("case %d: Compile succeeded, want error", i)
		}
	}
}

func BenchmarkMatch(b *testing.B) {
	e, _ := Compile(testRules)
	src, dst := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("8.8.8.8")
	b.ReportAllocs()
	for b.Loop() {
		e.Match(src, "www.example.com", dst)
	}
}
