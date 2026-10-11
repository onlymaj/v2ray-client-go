package share

import "testing"

// Regressions from the round-4 fuzzing pass.
func TestValidateRejectsBadAddressAndControlChars(t *testing.T) {
	for _, link := range []string{
		"vless://11111111-2222-3333-4444-555555555555@::1", // unbracketed IPv6 parsed as ":" port 1
		"vless://%00@example.com:443",                          // NUL id
		"vless://11111111-2222-3333-4444-555555555555@ex%00ample.com:443",
		"vless://11111111-2222-3333-4444-555555555555@example.com:443?flow=a%0Ab",
		"vless://11111111-2222-3333-4444-555555555555@example.com:443?fp=%07",
		"vless://11111111-2222-3333-4444-555555555555@example.com:443#a%01b",
	} {
		if c, err := Parse(link); err == nil {
			t.Errorf("Parse(%q) accepted: %+v", link, c)
		}
	}
}

func TestIPv6LinkRoundTrip(t *testing.T) {
	c, err := Parse("vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:443?security=none#v6")
	if err != nil {
		t.Fatal(err)
	}
	if c.Address != "2001:db8::1" {
		t.Fatalf("address %q", c.Address)
	}
	link, err := c.Link()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(link); err != nil {
		t.Fatalf("exported link %q does not parse: %v", link, err)
	}
}
