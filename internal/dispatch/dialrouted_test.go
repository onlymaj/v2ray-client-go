package dispatch

import (
	"bufio"
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// DNS queries are routed by the query name but must reach the configured
// upstream, never <qname>:53 (regression: any website could answer DNS for
// the whole LAN).
func TestDialRoutedKeepsDestination(t *testing.T) {
	d, err := New(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	up := outbound.Addr{IP: netip.MustParseAddr("1.2.3.4"), Port: 53} // rule r-a -> client a
	c, dec, err := d.DialRouted(context.Background(), lan, "attacker.example", up)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if dec.Kind != KindClient || dec.ClientID != "a" {
		t.Fatalf("decision %+v", dec)
	}
	// fakeProto sends the requested destination first; the echo server
	// returns it.
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(line); got != "1.2.3.4:53" {
		t.Fatalf("proxy asked for %q, want the upstream 1.2.3.4:53", got)
	}
}
