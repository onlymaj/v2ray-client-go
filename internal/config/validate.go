package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/router"
)

// MaxClients caps the number of clients so a malicious subscription or
// import can't exhaust the router's memory. A client costs about 6 KB, and
// 18 KB more of traffic and delay history once it has been used: 250 are
// up to 6.5 MiB of GOMEMLIMIT=32MiB, and 1000 were 23 to 26 MiB, which left
// no room for the connections (measured after round 21).
const MaxClients = 250

// MaxMemberships bounds the members of all groups together. Each costs
// about 150 bytes across the config and the dispatcher: 200 groups of 1000
// members were 36 MiB (round 21).
const MaxMemberships = 4000

// Validate checks references between clients, groups and rules, and that
// the rules compile. Protocol-specific fields are checked when the client's
// dialer is built.
func (c *Config) Validate() error {
	if len(c.Clients) > MaxClients {
		return fmt.Errorf("too many clients (%d, limit %d)", len(c.Clients), MaxClients)
	}
	if len(c.Groups) > 200 || len(c.Rules) > 1000 || len(c.Subscriptions) > 100 {
		return errors.New("too many groups, rules or subscriptions")
	}
	if h := c.Settings.RouterOS.CertSHA256; h != "" && !isHex64(strings.ReplaceAll(h, ":", "")) {
		return errors.New("routeros certSha256 must be 64 hex characters")
	}
	members := 0
	for _, g := range c.Groups {
		members += len(g.Members)
	}
	if members > MaxMemberships {
		return fmt.Errorf("too many group members in total (%d, limit %d)", members, MaxMemberships)
	}
	clients := map[string]bool{}
	for _, cl := range c.Clients {
		if cl.ID == "" {
			return errors.New("client without id")
		}
		if clients[cl.ID] {
			return fmt.Errorf("duplicate client id %q", cl.ID)
		}
		clients[cl.ID] = true
		if cl.Protocol != "vless" && cl.Protocol != "vmess" {
			return fmt.Errorf("client %q: unknown protocol %q", cl.Name, cl.Protocol)
		}
		if cl.Address == "" || cl.Port == 0 {
			return fmt.Errorf("client %q: address and port are required", cl.Name)
		}
	}
	groups := map[string]bool{}
	for _, g := range c.Groups {
		if g.ID == "" || groups[g.ID] {
			return fmt.Errorf("missing or duplicate group id %q", g.ID)
		}
		groups[g.ID] = true
		switch g.Strategy {
		case group.Failover, group.LeastPing, group.RoundRobin, group.Sticky:
		default:
			return fmt.Errorf("group %q: unknown strategy %q", g.Name, g.Strategy)
		}
		seen := map[string]bool{}
		for _, m := range g.Members {
			if !clients[m] {
				return fmt.Errorf("group %q: unknown member %q", g.Name, m)
			}
			// The group could not be built and every rule using it would
			// follow the kill switch (round 17).
			if seen[m] {
				return fmt.Errorf("group %q: member %q is listed twice", g.Name, m)
			}
			seen[m] = true
		}
	}
	for _, r := range c.Rules {
		switch r.Target.Kind {
		case router.KindClient:
			if !clients[r.Target.ID] {
				return fmt.Errorf("rule %q: unknown client %q", r.ID, r.Target.ID)
			}
		case router.KindGroup:
			if !groups[r.Target.ID] {
				return fmt.Errorf("rule %q: unknown group %q", r.ID, r.Target.ID)
			}
		}
	}
	if _, err := router.Compile(c.Rules); err != nil {
		return err
	}
	switch c.Settings.KillSwitch {
	case KillSwitchBlock, KillSwitchDirect:
	default:
		return fmt.Errorf("unknown kill switch mode %q", c.Settings.KillSwitch)
	}
	return c.Settings.validate()
}

// validate refuses settings the listeners, the health checker or the DNS
// forwarder could not use. A clash between ports would stop the next start
// with the UI unreachable, so it must never be saved.
// repair replaces settings that validate refuses with their defaults and
// returns what it changed. Open uses it: a config file written before these
// checks existed must not stop the start, which would leave the UI
// unreachable and the LAN without a proxy.
func (s *Settings) repair() []string {
	var fixed []string
	def := Default().Settings
	for range 6 { // each pass fixes the one field validate complains about
		err := s.validate()
		if err == nil {
			break
		}
		switch msg := err.Error(); {
		case strings.HasPrefix(msg, "healthInterval"):
			s.HealthInterval = def.HealthInterval
		case strings.HasPrefix(msg, "ports"):
			s.Ports = def.Ports
		case strings.HasPrefix(msg, "dnsUpstream"):
			s.DNSUpstream = def.DNSUpstream
		case strings.HasPrefix(msg, "routeros url must be https"):
			// The URL is the documented plain-HTTP setup; the pin is the
			// part that does nothing there (round 20).
			s.RouterOS.Enabled, s.RouterOS.CertSHA256 = false, ""
			fixed = append(fixed, msg+"; the RouterOS sync is turned off and certSha256 is cleared")
			continue
		case strings.HasPrefix(msg, "routeros url"):
			// The password goes with the URL it was entered for.
			s.RouterOS.Enabled, s.RouterOS.URL, s.RouterOS.Password = false, def.RouterOS.URL, ""
			fixed = append(fixed, msg+"; the RouterOS sync is turned off and its URL and password are reset")
			continue
		case strings.HasPrefix(msg, "routeros"):
			s.RouterOS.Enabled = false
			fixed = append(fixed, msg+"; the RouterOS sync is turned off")
			continue
		case strings.HasPrefix(msg, "healthUrl"):
			s.HealthURL = def.HealthURL
		}
		fixed = append(fixed, err.Error()+"; using the default instead")
	}
	return fixed
}

func (s *Settings) validate() error {
	if s.HealthInterval < 5 || s.HealthInterval > 3600 {
		return errors.New("healthInterval must be 5-3600 seconds")
	}
	p := s.Ports
	if p.Transparent == 0 || p.UI == 0 {
		return errors.New("ports.transparent and ports.ui must be 1-65535")
	}
	used := map[uint16]string{}
	for _, x := range []struct {
		name string
		port uint16
	}{{"transparent", p.Transparent}, {"ui", p.UI}, {"socks", p.SOCKS}, {"http", p.HTTP}, {"dns", p.DNS}} {
		if x.port == 0 {
			continue
		}
		if other := used[x.port]; other != "" {
			return fmt.Errorf("ports.%s and ports.%s must differ", other, x.name)
		}
		used[x.port] = x.name
	}
	if ap, err := netip.ParseAddrPort(s.DNSUpstream); err != nil || ap.Port() == 0 {
		return errors.New("dnsUpstream must be ip:port")
	} else if a := ap.Addr().Unmap(); a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
		// Queries sent to itself would come back in until every upstream
		// slot was taken (round 20).
		return errors.New("dnsUpstream must not be a loopback, unspecified or multicast address")
	}
	// An empty URL is allowed: ROS_URL can supply it.
	if r := s.RouterOS; r.URL != "" {
		u, err := url.Parse(r.URL)
		if err != nil || len(r.URL) > 2048 || u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" {
			return errors.New("routeros url must be an http or https URL")
		}
		if u.Scheme == "http" && r.CertSHA256 != "" {
			return errors.New("routeros url must be https when certSha256 is set: over http the certificate is never checked and the password is sent in clear text")
		}
	}
	if r := s.RouterOS; r.Enabled && r.AddressList == "" {
		return errors.New("routeros addressList is required when the sync is enabled")
	}
	if s.HealthURL != "" { // empty selects the default URL
		u, err := url.Parse(s.HealthURL)
		if err != nil || len(s.HealthURL) > 2048 || u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" {
			return errors.New("healthUrl must be an http or https URL")
		}
		if port := u.Port(); port != "" {
			if ap, err := netip.ParseAddrPort("0.0.0.0:" + port); err != nil || ap.Port() == 0 {
				return errors.New("healthUrl has a bad port")
			}
		}
	}
	return nil
}

// RemoveClient deletes a client and every reference to it (group members,
// rules that target it). If the default rule targets it, the rules listed
// after the default rule are deleted too.
func (c *Config) RemoveClient(id string) {
	out := c.Clients[:0]
	for _, cl := range c.Clients {
		if cl.ID != id {
			out = append(out, cl)
		}
	}
	c.Clients = out
	for i := range c.Groups {
		m := c.Groups[i].Members[:0]
		for _, x := range c.Groups[i].Members {
			if x != id {
				m = append(m, x)
			}
		}
		c.Groups[i].Members = m
	}
	rules := c.Rules[:0]
	for _, r := range c.Rules {
		if !(r.Target.Kind == router.KindClient && r.Target.ID == id) {
			rules = append(rules, r)
			continue
		}
		if r.Type == "default" {
			// Rules after the default rule never matched. Without the
			// default they would come to life, so they go with it.
			break
		}
	}
	c.Rules = rules
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
