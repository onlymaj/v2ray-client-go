package config

import (
	"errors"
	"fmt"

	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/router"
)

// Validate checks references between clients, groups and rules, and that
// the rules compile. Protocol-specific fields are checked when the client's
// dialer is built.
func (c *Config) Validate() error {
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
		for _, m := range g.Members {
			if !clients[m] {
				return fmt.Errorf("group %q: unknown member %q", g.Name, m)
			}
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
	if c.Settings.HealthInterval < 10 {
		return errors.New("health interval must be at least 10 seconds")
	}
	return nil
}

// RemoveClient deletes a client and every reference to it (group members,
// rules that target it).
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
		}
	}
	c.Rules = rules
}
