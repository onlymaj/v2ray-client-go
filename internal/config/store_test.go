package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/router"
	"os"
	"path/filepath"
	"strconv"
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
		// Round 18: these were saved and the sync then failed, or sent the
		// password in clear text past a pin, with nothing in the UI.
		"routeros url no scheme": func(s *Settings) { s.RouterOS.URL = "172.17.0.1" },
		"routeros pin over http": func(s *Settings) {
			s.RouterOS.URL, s.RouterOS.CertSHA256 = "http://172.17.0.1", strings.Repeat("ab", 32)
		},
		"routeros no list":      func(s *Settings) { s.RouterOS.Enabled, s.RouterOS.AddressList = true, "" },
		"socks on the ui port":  func(s *Settings) { s.Ports.SOCKS = s.Ports.UI },
		"dns on the http port":  func(s *Settings) { s.Ports.HTTP, s.Ports.DNS = 8118, 8118 },
		"ui port 0":             func(s *Settings) { s.Ports.UI = 0 },
		"transparent port 0":    func(s *Settings) { s.Ports.Transparent = 0 },
		"dns upstream name":     func(s *Settings) { s.DNSUpstream = "not an address" },
		"dns upstream loopback": func(s *Settings) { s.DNSUpstream = "127.0.0.1:53" }, // round 20
		"dns upstream mapped":   func(s *Settings) { s.DNSUpstream = "[::ffff:127.0.0.1]:53" },
		"dns upstream any":      func(s *Settings) { s.DNSUpstream = "0.0.0.0:53" },
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

// Round 15: encoding/json wrote '<', '>' and '&' as six bytes each, so a
// subscription of names made of them became a config six times its size.
func TestStoreDoesNotEscapeHTML(t *testing.T) {
	c := &Config{Clients: []Client{{ID: "a", Name: "<&>"}}}
	data, err := marshal(c, "  ")
	if err != nil || !bytes.Contains(data, []byte(`"<&>"`)) {
		t.Fatalf("marshal: %v\n%s", err, data)
	}
	got, err := clone(c)
	if err != nil || got.Clients[0].Name != "<&>" {
		t.Fatalf("clone: %v %+v", err, got)
	}
}

// Round 17: a group listing a member twice was saved, could not be built,
// and every rule using it followed the kill switch.
func TestDuplicateGroupMemberRefused(t *testing.T) {
	c := Default()
	c.Clients = []Client{{ID: "c1", Name: "n", Protocol: "vless", Address: "h.example", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555", Network: "tcp", TLS: "none"}}
	c.Groups[0].Members = []string{"c1"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	c.Groups[0].Members = []string{"c1", "c1"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicate member: %v", err)
	}
}

// Round 19: the repair of a RouterOS block that is now refused replaced a
// valid URL, kept the password beside the default URL, and did not say the
// sync was off.
func TestOpenRepairsRouterOSSettings(t *testing.T) {
	for name, tc := range map[string]struct {
		ros         string
		url, pass   string
		wantInFixed string
	}{
		"no list":       {`{"enabled":true,"url":"https://192.168.88.1","password":"p","addressList":""}`, "https://192.168.88.1", "p", "sync is turned off"},
		"pin over http": {`{"enabled":true,"url":"http://172.17.0.1","password":"p","addressList":"x","certSha256":"` + strings.Repeat("ab", 32) + `"}`, "http://172.17.0.1", "p", "certSha256 is cleared"},
		"no scheme":     {`{"enabled":true,"url":"192.168.88.1","password":"p","addressList":"x"}`, Default().Settings.RouterOS.URL, "", "password are reset"},
	} {
		c := Default()
		if err := json.Unmarshal([]byte(`{"settings":{"routeros":`+tc.ros+`}}`), c); err != nil {
			t.Fatal(err)
		}
		fixed := c.Settings.repair()
		r := c.Settings.RouterOS
		if r.Enabled || r.URL != tc.url || r.Password != tc.pass || len(fixed) != 1 || !strings.Contains(fixed[0], tc.wantInFixed) {
			t.Errorf("%s: %+v, fixed %q", name, r, fixed)
		}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: still refused: %v", name, err)
		}
	}
}

// Round 19: the temporary file of a save cut short by a power loss stayed
// in the config directory for ever.
func TestOpenRemovesLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, ".config-123456.json")
	other := filepath.Join(dir, ".config-backup.json") // round 20: the admin's own
	for _, f := range []string{left, other} {
		if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Fatalf("leftover temp file still there: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("an unrelated file was removed: %v", err)
	}
}

// Round 21: nothing bounded the config as a whole. A subscription at its
// body limit made one of 3 MiB, which cost 10 to 15 MiB on every save, and
// 200 groups of 1000 members were 36 MiB.
func TestConfigSizeLimits(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = s.Update(func(c *Config) error {
		c.Groups[0].Name = strings.Repeat("n", MaxFileSize)
		return nil
	})
	if !errors.Is(err, ErrTooLarge) || len(s.Get().Groups[0].Name) > 100 {
		t.Fatalf("a config over the size limit: %v", err)
	}
	c := Default()
	for i := range 5 {
		id := "c" + strconv.Itoa(i)
		c.Clients = append(c.Clients, Client{ID: id, Name: id, Protocol: "vless", Address: "h.example", Port: 443,
			UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Network: "tcp", Enabled: true})
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("test config: %v", err)
	}
	for g := 0; g*5 <= MaxMemberships; g++ {
		c.Groups = append(c.Groups, group.Group{ID: "g" + strconv.Itoa(g), Name: "g", Strategy: group.Failover,
			Members: []string{"c0", "c1", "c2", "c3", "c4"}})
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "too many group") {
		t.Fatalf("%d memberships: %v", len(c.Groups)*5, err)
	}
}
