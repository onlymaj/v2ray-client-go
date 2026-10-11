// Package routeros keeps a RouterOS firewall address list (e.g. "no-proxy")
// in sync with the addresses of the enabled proxy servers, so the router's
// mangle/routing rules can send traffic to them around the container
// instead of looping it back through the proxy.
//
// The Syncer talks to the RouterOS v7 REST API (/rest/ip/firewall/
// address-list). It owns only entries whose comment is "v2ray-client-go": it
// adds missing server addresses with that comment and removes owned
// entries that are no longer wanted. Entries with any other comment are
// never modified; an address already present in the list under another
// comment is not added again.
//
// Only IPv4 is synced: hostnames are resolved to A records and IPv6
// literals are skipped.
//
// Hostnames are resolved with the system resolver (resolv.conf). Point the
// container's resolv.conf at the RouterOS DNS (or another resolver), not
// at the container's own DNS forwarder: the forwarder may route queries
// through the very proxies whose addresses are being resolved.
package routeros

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// OwnerComment marks entries the Syncer manages.
const OwnerComment = "v2ray-client-go"

type Options struct {
	// Resolve returns the IPv4 addresses of host. Default: the system
	// resolver's A records.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// VerifyTLS enables certificate verification. Off by default because
	// RouterOS ships a self-signed certificate.
	VerifyTLS bool
	// HTTPClient overrides the client built from the config (tests).
	HTTPClient *http.Client

	ResolveInterval time.Duration // default 5m
	ResyncInterval  time.Duration // default 10m
	MinBackoff      time.Duration // default 5s
	MaxBackoff      time.Duration // default 5m
	Logf            func(format string, args ...any)
}

// Status is the outcome of the last sync attempt.
type Status struct {
	LastSync  time.Time `json:"lastSync"` // last successful sync; zero if none
	LastError string    `json:"lastError,omitempty"`
	Entries   int       `json:"entries"` // owned entries after the last successful sync
}

type config struct {
	enabled                           bool
	url, user, pass, list, certSHA256 string
}

type Syncer struct {
	opts Options
	wake chan struct{}

	mu     sync.Mutex
	cfg    config
	hosts  []string
	gen    int // bumped by SetConfig / SetServers
	status Status

	pass int // resolve passes so far; used by Run's goroutine only
}

func New(opts Options) *Syncer {
	if opts.Resolve == nil {
		opts.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		}
	}
	if opts.ResolveInterval <= 0 {
		opts.ResolveInterval = 5 * time.Minute
	}
	if opts.ResyncInterval <= 0 {
		opts.ResyncInterval = 10 * time.Minute
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = 5 * time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 5 * time.Minute
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &Syncer{opts: opts, wake: make(chan struct{}, 1)}
}

// SetConfig updates the router connection settings. The caller merges the
// ROS_URL / ROS_USER / ROS_PASS environment overrides beforehand.
// certSHA256 pins the router's leaf certificate (see NewClient); empty
// means no verification unless Options.VerifyTLS is set.
func (s *Syncer) SetConfig(enabled bool, url, user, pass, list, certSHA256 string) {
	s.mu.Lock()
	c := config{enabled, url, user, pass, list, certSHA256}
	if c != s.cfg {
		s.cfg = c
		s.gen++
	}
	s.mu.Unlock()
	s.poke()
}

// SetServers sets the addresses (IPs or hostnames) of the enabled clients
// and triggers a re-resolve.
func (s *Syncer) SetServers(hosts []string) {
	s.mu.Lock()
	s.hosts = slices.Clone(hosts)
	s.gen++
	s.mu.Unlock()
	s.poke()
}

func (s *Syncer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Syncer) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run syncs until ctx is cancelled. The address list is written only when
// the desired set or the config changed, every ResyncInterval, and on
// retries after a failure (exponential backoff up to MaxBackoff).
func (s *Syncer) Run(ctx context.Context) {
	var (
		seenGen      = -1
		resolved     = map[string][]netip.Addr{} // last good result per host
		desired      []string
		resolveErr   error
		resolveFails int
		nextResolve  time.Time

		appliedKey string
		syncErr    error
		syncFails  int
		nextSync   time.Time

		clientCfg config
		client    *Client
		warned    bool
	)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		s.mu.Lock()
		cfg, hosts, gen := s.cfg, s.hosts, s.gen
		s.mu.Unlock()
		now := time.Now()
		var wakeAt time.Time

		if cfg.enabled && cfg.url != "" && cfg.list != "" {
			if gen != seenGen || !now.Before(nextResolve) {
				seenGen = gen
				desired, resolveErr = s.resolveAll(ctx, hosts, resolved)
				if resolveErr != nil {
					resolveFails++
					nextResolve = now.Add(s.backoff(resolveFails))
				} else {
					resolveFails = 0
					nextResolve = now.Add(s.opts.ResolveInterval)
				}
			}

			if client == nil || cfg != clientCfg {
				clientCfg = cfg
				if s.opts.HTTPClient != nil {
					client = newClient(cfg.url, cfg.user, cfg.pass, s.opts.HTTPClient)
				} else {
					client = NewClient(cfg.url, cfg.user, cfg.pass, !s.opts.VerifyTLS, cfg.certSHA256)
					if cfg.certSHA256 == "" && !s.opts.VerifyTLS && !warned {
						warned = true
						s.opts.Logf("routeros: certSha256 is not set; the router's TLS certificate is not verified and the password can be intercepted")
					}
				}
			}
			key := fmt.Sprint(cfg, desired, resolveErr == nil)
			if key != appliedKey || !now.Before(nextSync) {
				n, err := s.reconcile(ctx, client, cfg.list, desired, resolveErr == nil)
				if ctx.Err() != nil {
					return
				}
				syncErr = err
				if err != nil {
					syncFails++
					nextSync = time.Now().Add(s.backoff(syncFails))
					s.opts.Logf("routeros: sync failed (retry in %s): %v", s.backoff(syncFails), err)
				} else {
					syncFails = 0
					appliedKey = key
					nextSync = time.Now().Add(s.opts.ResyncInterval)
					s.mu.Lock()
					s.status.LastSync, s.status.Entries = time.Now(), n
					s.mu.Unlock()
				}
			}
			s.mu.Lock()
			s.status.LastError = ""
			if err := errors.Join(syncErr, resolveErr); err != nil {
				s.status.LastError = err.Error()
			}
			s.mu.Unlock()
			wakeAt = nextResolve
			if nextSync.Before(wakeAt) {
				wakeAt = nextSync
			}
		} else {
			// Disabled: force a full sync when re-enabled.
			appliedKey, seenGen = "", -1
			nextResolve, nextSync = time.Time{}, time.Time{}
		}

		var tc <-chan time.Time
		if !wakeAt.IsZero() {
			timer.Reset(max(time.Until(wakeAt), 0))
			tc = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-tc:
		}
	}
}

func (s *Syncer) backoff(fails int) time.Duration {
	d := s.opts.MinBackoff
	for i := 1; i < fails && d < s.opts.MaxBackoff; i++ {
		d *= 2
	}
	return min(d, s.opts.MaxBackoff)
}

// Bounds on what one sync pass resolves and sends to the router.
const (
	maxAddrsPerHost = 8
	maxAddrs        = 2048
	maxResolvePass  = 2 * time.Minute
)

// resolveAll returns the sorted, de-duplicated IPv4 addresses of hosts.
// A host that fails to resolve keeps its last good addresses in cache so a
// transient DNS failure does not remove it from the router.
func (s *Syncer) resolveAll(ctx context.Context, hosts []string, cache map[string][]netip.Addr) ([]string, error) {
	// One pass may not take longer than this in total, or a subscription
	// with many slow host names would keep the loop from seeing config
	// changes for hours. Hosts not reached keep their cached addresses.
	ctx, cancelAll := context.WithTimeout(ctx, maxResolvePass)
	defer cancelAll()
	// The deadline can end a pass early. Names never resolved go first and
	// the rest start one further on each pass, so the same names at the end
	// of the list are not the ones skipped every time.
	s.pass++
	var fresh, known []string
	for _, h := range hosts {
		if _, ok := cache[strings.Trim(strings.TrimSpace(h), "[]")]; ok {
			known = append(known, h)
		} else {
			fresh = append(fresh, h)
		}
	}
	if n := len(known); n > 0 {
		k := s.pass % n
		known = append(known[k:n:n], known[:k]...)
	}
	hosts = append(fresh, known...)
	set := map[string]bool{}
	var errs []error
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.Trim(strings.TrimSpace(h), "[]")
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if ip, err := netip.ParseAddr(h); err == nil {
			if ip = ip.Unmap(); ip.Is4() {
				set[ip.String()] = true
			}
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ips, err := s.opts.Resolve(rctx, h)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve %s: %w", h, err))
			ips = cache[h]
		} else {
			// A host name from a subscription can resolve to thousands of
			// addresses; each would become a firewall entry on the router.
			slices.SortFunc(ips, netip.Addr.Compare) // which ones are kept must not vary
			ips = ips[:min(len(ips), maxAddrsPerHost)]
			cache[h] = ips
		}
		for _, ip := range ips {
			if ip = ip.Unmap(); ip.Is4() && len(set) < maxAddrs {
				set[ip.String()] = true
			}
		}
	}
	for h := range cache {
		if !seen[h] {
			delete(cache, h)
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	slices.Sort(out)
	return out, errors.Join(errs...)
}

// normAddr turns "1.2.3.4/32" into "1.2.3.4"; other values pass through.
func normAddr(a string) string {
	if p, err := netip.ParsePrefix(a); err == nil && p.IsSingleIP() {
		return p.Addr().String()
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		return ip.String()
	}
	return a
}

// reconcile makes the owned entries of list equal desired and returns the
// number of owned entries afterwards. With remove false (some hostname
// failed to resolve, e.g. DNS not up yet at boot) it only adds.
func (s *Syncer) reconcile(ctx context.Context, c *Client, list string, desired []string, remove bool) (int, error) {
	entries, err := c.List(ctx, list)
	if err != nil {
		return 0, err
	}
	want := map[string]bool{}
	for _, a := range desired {
		want[a] = true
	}
	present := map[string]bool{}
	var stale []Entry
	owned := 0
	isOwned := func(e Entry) bool { return e.Comment == OwnerComment && e.Dynamic != "true" }
	for _, e := range entries {
		if !isOwned(e) {
			present[normAddr(e.Address)] = true
		}
	}
	for _, e := range entries {
		a := normAddr(e.Address)
		if !isOwned(e) {
			continue
		}
		if !want[a] && !remove {
			owned++
			continue
		}
		if !want[a] || present[a] {
			stale = append(stale, e) // unwanted or duplicate
			continue
		}
		present[a] = true
		owned++
	}

	var errs []error
	for _, e := range stale {
		if err := c.Remove(ctx, e.ID); err != nil {
			errs = append(errs, err)
			owned++
		} else {
			s.opts.Logf("routeros: removed %s from %s", e.Address, list)
		}
	}
	for _, a := range desired {
		if present[a] {
			continue
		}
		if err := c.Add(ctx, Entry{List: list, Address: a, Comment: OwnerComment}); err != nil {
			errs = append(errs, err)
		} else {
			owned++
			s.opts.Logf("routeros: added %s to %s", a, list)
		}
	}
	return owned, errors.Join(errs...)
}
