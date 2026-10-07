// Package router matches connections against an ordered rule list.
//
// Rule types:
//   - "source": Values are client IPs or CIDRs, matched against the source.
//   - "dest":   Values are IPs or CIDRs, matched against the destination IP.
//   - "domain": Values are domains. "example.com" matches exactly that name;
//     "*.example.com" matches any subdomain (a.example.com, a.b.example.com)
//     but NOT example.com itself — list both to cover both. Matching is
//     case-insensitive and ignores a trailing dot.
//   - "default": the fallback, used when no other rule matches regardless of
//     its position in the list. At most one is allowed.
//
// Rules are evaluated top to bottom; the first match wins.
package router

import (
	"fmt"
	"net/netip"
	"strings"
)

// Target kinds. KindBlock is optional; callers may reject it in the UI.
const (
	KindClient = "client"
	KindGroup  = "group"
	KindDirect = "direct"
	KindBlock  = "block"
)

type Target struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"` // client or group ID
}

type Rule struct {
	ID     string   `json:"id"`
	Type   string   `json:"type"` // "source" | "domain" | "dest" | "default"
	Values []string `json:"values,omitempty"`
	Target Target   `json:"target"`
}

type compiled struct {
	rule     *Rule
	prefixes []netip.Prefix
	exact    map[string]struct{}
	suffix   map[string]struct{} // "*.x" stored as "x"
}

// Engine is an immutable compiled rule set, safe for concurrent use. Swap
// it atomically (atomic.Pointer[Engine]) when rules change.
type Engine struct {
	rules []compiled
	def   *Rule
}

// Compile validates rules and builds an Engine. The rules slice is copied.
func Compile(rules []Rule) (*Engine, error) {
	e := &Engine{}
	for i := range rules {
		r := rules[i]
		r.Values = append([]string(nil), r.Values...)
		if err := checkTarget(r.Target); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		c := compiled{rule: &r}
		switch r.Type {
		case "default":
			if e.def != nil {
				return nil, fmt.Errorf("rule %q: more than one default rule", r.ID)
			}
			e.def = &r
			continue
		case "source", "dest":
			for _, v := range r.Values {
				p, err := parsePrefix(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("rule %q: %w", r.ID, err)
				}
				c.prefixes = append(c.prefixes, p)
			}
		case "domain":
			c.exact, c.suffix = map[string]struct{}{}, map[string]struct{}{}
			for _, v := range r.Values {
				d := normDomain(strings.TrimSpace(v))
				set := c.exact
				if s, ok := strings.CutPrefix(d, "*."); ok {
					d, set = s, c.suffix
				}
				if d == "" || strings.ContainsAny(d, "*/: ") {
					return nil, fmt.Errorf("rule %q: invalid domain %q", r.ID, v)
				}
				set[d] = struct{}{}
			}
		default:
			return nil, fmt.Errorf("rule %q: unknown type %q", r.ID, r.Type)
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

func checkTarget(t Target) error {
	switch t.Kind {
	case KindClient, KindGroup:
		if t.ID == "" {
			return fmt.Errorf("target %s needs an id", t.Kind)
		}
	case KindDirect, KindBlock:
	default:
		return fmt.Errorf("unknown target kind %q", t.Kind)
	}
	return nil
}

// parsePrefix accepts a CIDR or a bare IP (treated as a host route).
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func normDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}

// Match returns the first rule matching the connection, or the default rule.
// domain may be empty (not sniffed); src/dst may be invalid (unknown), in
// which case rules on them do not match. It returns nil when nothing
// matches and there is no default rule. The returned Rule must not be
// modified.
func (e *Engine) Match(src netip.Addr, domain string, dst netip.Addr) *Rule {
	src, dst = src.Unmap(), dst.Unmap()
	domain = normDomain(domain)
	for i := range e.rules {
		c := &e.rules[i]
		var ok bool
		switch c.rule.Type {
		case "source":
			ok = containsAddr(c.prefixes, src)
		case "dest":
			ok = containsAddr(c.prefixes, dst)
		case "domain":
			ok = c.matchDomain(domain)
		}
		if ok {
			return c.rule
		}
	}
	return e.def
}

// Len returns the number of non-default rules.
func (e *Engine) Len() int { return len(e.rules) }

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (c *compiled) matchDomain(d string) bool {
	if d == "" {
		return false
	}
	if _, ok := c.exact[d]; ok {
		return true
	}
	if len(c.suffix) == 0 {
		return false
	}
	for i := 0; i < len(d); i++ {
		if d[i] == '.' {
			if _, ok := c.suffix[d[i+1:]]; ok {
				return true
			}
		}
	}
	return false
}
