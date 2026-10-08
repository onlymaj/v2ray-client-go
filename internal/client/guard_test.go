package client

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/netguard"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// The other tests run their fake servers on loopback.
func TestMain(m *testing.M) {
	refusedServer = func(ip netip.Addr) bool { return !ip.Unmap().IsLoopback() && netguard.Refused(ip) }
	os.Exit(m.Run())
}

func TestServerGuard(t *testing.T) {
	old := refusedServer
	refusedServer = netguard.Refused
	t.Cleanup(func() { refusedServer = old })
	cases := []struct {
		addr         string
		blockPrivate bool
		refused      bool
	}{
		{"127.0.0.1:443", false, true},
		{"[::1]:443", false, true},
		{"[::ffff:127.0.0.1]:443", false, true},
		{"0.0.0.0:443", false, true},
		{"169.254.169.254:80", false, true},
		{"[fe80::1%eth0]:443", false, true},
		{"192.168.88.1:443", false, false},
		{"192.168.88.1:443", true, true},
		{"100.64.1.1:443", true, true},
		{"[fd00::1]:443", true, true},
		{"203.0.113.5:443", true, false},
	}
	for _, tc := range cases {
		err := serverGuard(tc.blockPrivate)("tcp", tc.addr, nil)
		if (err != nil) != tc.refused {
			t.Errorf("%s blockPrivate=%v: err %v, want refused=%v", tc.addr, tc.blockPrivate, err, tc.refused)
		}
	}
}

// A subscription client pointing at a private server is refused on every
// dial path (DialServer, Probe, Dial) unless AllowPrivate is set; a client
// added by hand is not.
func TestBuildRefusesPrivateSubscriptionServer(t *testing.T) {
	fakeProtocol(t, "vless")
	old := refusedServer
	// Loopback stands in for a private address here.
	refusedServer = func(netip.Addr) bool { return false }
	t.Cleanup(func() { refusedServer = old })
	oldPriv := isPrivate
	isPrivate = func(ip netip.Addr) bool { return ip.Unmap().IsLoopback() }
	t.Cleanup(func() { isPrivate = oldPriv })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	mk := func(sub string) config.Client {
		c := base()
		c.Address, c.Port, c.TLS = "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port), "none"
		c.SubscriptionID = sub
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dest := outbound.Addr{Domain: "x.test", Port: 80}
	for _, tc := range []struct {
		sub     string
		allow   bool
		refused bool
	}{{"s1", false, true}, {"s1", true, false}, {"", false, false}} {
		cl, err := Build(mk(tc.sub), Options{AllowPrivate: tc.allow})
		if err != nil {
			t.Fatal(err)
		}
		_, err1 := cl.DialServer(ctx)
		_, err2 := cl.Probe(ctx, "tcp", dest)
		_, err3 := cl.Dial(ctx, "tcp", dest)
		cl.Close()
		for i, err := range []error{err1, err2, err3} {
			got := err != nil && strings.Contains(err.Error(), "server address")
			if got != tc.refused {
				t.Errorf("sub=%q allow=%v path %d: err %v, want refused=%v", tc.sub, tc.allow, i, err, tc.refused)
			}
		}
	}
}
