// Package dispatch decides where each connection goes (a client, direct or
// block) from the rules, groups and health state, dials it and relays the
// data.
package dispatch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/client"
	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/router"
)

// Decision kinds.
const (
	KindClient = "client"
	KindDirect = "direct"
	KindBlock  = "block"
)

// Decision is the routing result for one connection.
type Decision struct {
	RuleID     string
	Kind       string // KindClient | KindDirect | KindBlock
	ClientID   string
	GroupID    string
	KillSwitch bool // the rule's target was unavailable
}

// ErrBlocked is returned by Dial for connections routed to block.
var ErrBlocked = errors.New("dispatch: blocked")

type clientEntry struct {
	cfg          config.Client
	allowPrivate bool           // client.Options.AllowPrivate it was built with
	c            *client.Client // nil if Build failed
}

type groupEntry struct {
	g   group.Group
	sel *group.Selector // nil if the group is invalid (e.g. no members)
}

// state is an immutable snapshot swapped atomically on Update.
type state struct {
	engine     *router.Engine
	clients    map[string]*clientEntry
	groups     map[string]*groupEntry
	killSwitch string
}

type health struct {
	up    bool
	delay time.Duration
}

// Dispatcher is safe for concurrent use.
type Dispatcher struct {
	st       atomic.Pointer[state]
	tracker  Tracker
	direct   outbound.Direct
	onChange atomic.Pointer[func(groupID, current string)]

	mu     sync.Mutex // serializes Update and HealthUpdate
	health map[string]health
}

// New builds a Dispatcher from cfg. tracker may be nil. A non-nil error
// from a client or group build failure does not prevent use; see Update.
func New(cfg *config.Config, tracker Tracker) (*Dispatcher, error) {
	if tracker == nil {
		tracker = nopTracker{}
	}
	d := &Dispatcher{
		tracker: tracker,
		direct:  outbound.Direct{Dialer: net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}},
		health:  map[string]health{},
	}
	d.st.Store(&state{engine: &router.Engine{}, clients: map[string]*clientEntry{}, groups: map[string]*groupEntry{}})
	return d, d.Update(cfg)
}

// Update applies a new config. Unchanged clients and groups are kept
// (pooled conns, group state); changed ones are rebuilt and fed the last
// known health; removed clients are closed. If the rules fail to compile
// nothing changes and the error is returned. Client or group build errors
// are returned too, but the rest of the config is applied and those
// clients/groups are treated as unavailable (kill switch).
func (d *Dispatcher) Update(cfg *config.Config) error {
	eng, err := router.Compile(cfg.Rules)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	old := d.st.Load()
	ns := &state{
		engine:     eng,
		clients:    make(map[string]*clientEntry, len(cfg.Clients)),
		groups:     make(map[string]*groupEntry, len(cfg.Groups)),
		killSwitch: cfg.Settings.KillSwitch,
	}
	var errs []error
	opts := client.Options{AllowPrivate: cfg.Settings.AllowPrivateServers}
	for _, cc := range cfg.Clients {
		// SameTransport ignores SubscriptionID, which decides together with
		// opts whether private servers are allowed: rebuild when that flips.
		if oe := old.clients[cc.ID]; oe != nil && client.SameTransport(oe.cfg, cc) &&
			oe.cfg.SubscriptionID == cc.SubscriptionID && oe.allowPrivate == opts.AllowPrivate {
			ns.clients[cc.ID] = &clientEntry{cfg: cc, allowPrivate: opts.AllowPrivate, c: oe.c}
			continue
		}
		c, err := client.Build(cc, opts)
		if err != nil {
			errs = append(errs, err)
		}
		ns.clients[cc.ID] = &clientEntry{cfg: cc, allowPrivate: opts.AllowPrivate, c: c}
	}
	for _, g := range cfg.Groups {
		if oe := old.groups[g.ID]; oe != nil && oe.sel != nil && reflect.DeepEqual(oe.g, g) {
			ns.groups[g.ID] = oe
			// Members whose availability changed get their new health.
			for _, id := range g.Members {
				if old.usable(id) != ns.usable(id) {
					d.feed(ns, oe.sel, id)
				}
			}
			continue
		}
		e := &groupEntry{g: g}
		if len(g.Members) > 0 {
			gid := g.ID
			e.sel, err = group.New(g, func(_, to string) { d.notify(gid, to) })
			if err != nil {
				errs = append(errs, err)
			}
		}
		if e.sel != nil {
			for _, id := range g.Members {
				d.feed(ns, e.sel, id)
			}
		}
		ns.groups[g.ID] = e
	}
	d.st.Store(ns)
	for id, oe := range old.clients {
		if oe.c != nil {
			if ne := ns.clients[id]; ne == nil || ne.c != oe.c {
				oe.c.Close()
			}
		}
	}
	return errors.Join(errs...)
}

// feed reports a member's last known health (down if unavailable).
func (d *Dispatcher) feed(st *state, sel *group.Selector, id string) {
	if !st.usable(id) {
		sel.Update(id, false, 0)
		return
	}
	if h, ok := d.health[id]; ok {
		sel.Update(id, h.up, h.delay)
	}
}

func (st *state) usable(id string) bool {
	e := st.clients[id]
	return e != nil && e.cfg.Enabled && e.c != nil
}

func (d *Dispatcher) notify(groupID, current string) {
	if f := d.onChange.Load(); f != nil {
		(*f)(groupID, current)
	}
}

// OnGroupChange sets the callback called when the current member of a
// failover or least-ping group changes (current is "" when none is up).
// It runs synchronously from HealthUpdate/Update and must not call them.
func (d *Dispatcher) OnGroupChange(f func(groupID, current string)) {
	d.onChange.Store(&f)
}

// HealthUpdate records a health-check result and forwards it to every
// group containing the client. Disabled or broken clients are reported
// down to the groups.
func (d *Dispatcher) HealthUpdate(clientID string, up bool, delay time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.health[clientID] = health{up, delay}
	st := d.st.Load()
	if !st.usable(clientID) {
		up, delay = false, 0
	}
	for _, g := range st.groups {
		if g.sel != nil {
			g.sel.Update(clientID, up, delay)
		}
	}
}

// Client returns the built client with id (enabled or not), or nil.
func (d *Dispatcher) Client(id string) *client.Client {
	if e := d.st.Load().clients[id]; e != nil {
		return e.c
	}
	return nil
}

// GroupCurrent returns the active member of a failover/least-ping group.
func (d *Dispatcher) GroupCurrent(id string) string {
	if g := d.st.Load().groups[id]; g != nil && g.sel != nil {
		return g.sel.Current()
	}
	return ""
}

// GroupStatus returns the members' last reported health, or nil.
func (d *Dispatcher) GroupStatus(id string) []group.MemberStatus {
	if g := d.st.Load().groups[id]; g != nil && g.sel != nil {
		return g.sel.Status()
	}
	return nil
}

// Route decides where a connection goes. domain may be empty; src/dst may
// be invalid.
func (d *Dispatcher) Route(src netip.Addr, domain string, dst netip.Addr) Decision {
	st := d.st.Load()
	r := st.engine.Match(src, domain, dst)
	if r == nil {
		return st.kill(Decision{})
	}
	dec := Decision{RuleID: r.ID}
	switch r.Target.Kind {
	case router.KindDirect:
		dec.Kind = KindDirect
	case router.KindBlock:
		dec.Kind = KindBlock
	case router.KindClient:
		if !st.usable(r.Target.ID) {
			return st.kill(dec)
		}
		dec.Kind, dec.ClientID = KindClient, r.Target.ID
	case router.KindGroup:
		dec.GroupID = r.Target.ID
		g := st.groups[r.Target.ID]
		if g == nil || g.sel == nil {
			return st.kill(dec)
		}
		key := domain
		if key == "" && dst.IsValid() {
			key = dst.String()
		}
		id, ok := g.sel.Pick(src, key)
		if !ok || !st.usable(id) {
			return st.kill(dec)
		}
		dec.Kind, dec.ClientID = KindClient, id
	default:
		return st.kill(dec)
	}
	return dec
}

func (st *state) kill(dec Decision) Decision {
	dec.KillSwitch = true
	if st.killSwitch == config.KillSwitchDirect {
		dec.Kind = KindDirect
	} else {
		dec.Kind = KindBlock
	}
	return dec
}

// Dial routes and opens a connection to dst. domain (sniffed or known)
// takes precedence over dst.Domain for routing; for proxied connections
// it also replaces the destination (like Xray destOverride), so the
// server resolves it. Direct connections keep the original destination.
func (d *Dispatcher) Dial(ctx context.Context, src netip.Addr, domain string, dst outbound.Addr) (net.Conn, Decision, error) {
	if domain == "" {
		domain = dst.Domain
	}
	dec := d.Route(src, domain, dst.IP)
	c, err := d.dial(ctx, dec, domain, dst)
	return c, dec, err
}

func (d *Dispatcher) dial(ctx context.Context, dec Decision, domain string, dst outbound.Addr) (net.Conn, error) {
	switch dec.Kind {
	case KindDirect:
		return d.direct.Dial(ctx, "tcp", dst)
	case KindClient:
		c := d.Client(dec.ClientID)
		if c == nil { // removed by a concurrent Update
			return nil, errors.New("dispatch: client " + dec.ClientID + " gone")
		}
		if domain != "" {
			dst = outbound.Addr{Domain: domain, Port: dst.Port}
		}
		return c.Dial(ctx, "tcp", dst)
	}
	return nil, ErrBlocked
}

// Close closes every client.
func (d *Dispatcher) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.st.Load().clients {
		if e.c != nil {
			e.c.Close()
		}
	}
}
