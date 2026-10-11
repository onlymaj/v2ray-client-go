package config

import (
	"github.com/onlymaj/v2ray-client-go/internal/router"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Regression (round 6): overlapping Updates must never leave subscribers on
// an older snapshot than the store holds.
func TestStoreNotifiesLatestInOrder(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var applied int
	s.OnChange(func(c *Config) {
		time.Sleep(time.Millisecond) // widen the race window
		mu.Lock()
		applied = c.Settings.HealthInterval
		mu.Unlock()
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			if err := s.Update(func(c *Config) error { c.Settings.HealthInterval = v; return nil }); err != nil {
				t.Error(err)
			}
		}(10 + i)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if want := s.Get().Settings.HealthInterval; applied != want {
		t.Fatalf("subscriber applied %d, store holds %d", applied, want)
	}
}

// Round 8: settings were saved unchecked. Two listeners on one port (SOCKS
// set to the UI port in the form) stopped the next start with the UI
// unreachable; a bad dnsUpstream or healthUrl was stored and then ignored.
func TestSettingsValidation(t *testing.T) {
	ok := Default()
	if err := ok.Validate(); err != nil {
		t.Fatalf("default config: %v", err)
	}
	ok.Settings.RouterOS.CertSHA256 = strings.Repeat("AB:", 31) + "ab" // colons as openssl prints them
	ok.Settings.HealthURL = ""
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid settings refused: %v", err)
	}
	for name, mut := range map[string]func(*Settings){
		"socks on the ui port":  func(s *Settings) { s.Ports.SOCKS = s.Ports.UI },
		"dns on the http port":  func(s *Settings) { s.Ports.HTTP, s.Ports.DNS = 8118, 8118 },
		"ui port 0":             func(s *Settings) { s.Ports.UI = 0 },
		"transparent port 0":    func(s *Settings) { s.Ports.Transparent = 0 },
		"dns upstream name":     func(s *Settings) { s.DNSUpstream = "not an address" },
		"dns upstream no port":  func(s *Settings) { s.DNSUpstream = "1.1.1.1" },
		"dns upstream port 0":   func(s *Settings) { s.DNSUpstream = "1.1.1.1:0" },
		"health url scheme":     func(s *Settings) { s.HealthURL = "ftp://x/" },
		"health url no host":    func(s *Settings) { s.HealthURL = "http:///x" },
		"health url port":       func(s *Settings) { s.HealthURL = "http://x:99999/" },
		"interval too small":    func(s *Settings) { s.HealthInterval = 4 },
		"interval overflows":    func(s *Settings) { s.HealthInterval = 1000000000000 },
		"cert pin wrong length": func(s *Settings) { s.RouterOS.CertSHA256 = "ab:cd" },
	} {
		c := Default()
		mut(&c.Settings)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Round 9: the settings checks added in round 8 also ran when the config
// file was loaded, so a file an older build had written (a bare-IP
// dnsUpstream, a mistyped health URL, a port used twice) stopped the start.
// Open replaces such settings with the defaults and keeps the rest.
func TestOpenRepairsOldSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	old := `{"clients":[],"groups":[],"rules":[],"subscriptions":[],"settings":{
		"ports":{"transparent":12345,"socks":80,"http":0,"dns":53,"ui":80},
		"healthUrl":"htttp://www.gstatic.com/generate_204","healthInterval":7200,
		"killSwitch":"direct","dnsUpstream":"1.1.1.1",
		"routeros":{"enabled":true,"url":"https://172.17.0.1","user":"u","addressList":"mine"}}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("old config refused: %v", err)
	}
	got, def := s.Get().Settings, Default().Settings
	if got.Ports != def.Ports || got.HealthURL != def.HealthURL || got.HealthInterval != def.HealthInterval || got.DNSUpstream != def.DNSUpstream {
		t.Fatalf("not repaired: %+v", got)
	}
	if got.KillSwitch != "direct" || got.RouterOS.AddressList != "mine" || !got.RouterOS.Enabled {
		t.Fatalf("valid settings were lost: %+v", got)
	}
}

// Round 9: deleting the client the default rule targets deleted the default
// rule, and the rules parked below it (dead since round 8, greyed out in
// the UI) came to life. A subscription dropping a server could do that.
func TestRemoveClientDropsRulesAfterDefault(t *testing.T) {
	c := Default()
	c.Clients = []Client{{ID: "x", Protocol: "vless", Address: "h", Port: 1}}
	c.Rules = []router.Rule{
		{ID: "a", Type: "dest", Values: []string{"1.1.1.1"}, Target: router.Target{Kind: router.KindDirect}},
		{ID: "b", Type: "dest", Values: []string{"2.2.2.2"}, Target: router.Target{Kind: router.KindClient, ID: "x"}},
		{ID: "def", Type: "default", Target: router.Target{Kind: router.KindClient, ID: "x"}},
		{ID: "dead", Type: "domain", Values: []string{"ir"}, Target: router.Target{Kind: router.KindDirect}},
	}
	c.RemoveClient("x")
	if len(c.Rules) != 1 || c.Rules[0].ID != "a" {
		t.Fatalf("rules after removal: %+v", c.Rules)
	}
}
