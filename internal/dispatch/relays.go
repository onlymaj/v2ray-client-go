package dispatch

import (
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/onlymaj/v2ray-client-go/internal/client"
)

// activeRelay is one established relay, remembered so that a config or
// health change can cut it if its route is no longer what the new state
// would choose (e.g. the kill switch moved from direct to block, a rule now
// sends the destination through a proxy, or the client was disabled).
type activeRelay struct {
	src    netip.Addr
	domain string
	dstIP  netip.Addr
	dec    Decision
	cli    *client.Client // the client object it was dialed through (KindClient)
	in     net.Conn
	out    net.Conn
}

type relaySet struct {
	mu sync.Mutex
	m  map[*activeRelay]struct{}
}

func (s *relaySet) add(r *activeRelay) {
	s.mu.Lock()
	if s.m == nil {
		s.m = map[*activeRelay]struct{}{}
	}
	s.m[r] = struct{}{}
	s.mu.Unlock()
}

func (s *relaySet) remove(r *activeRelay) {
	s.mu.Lock()
	delete(s.m, r)
	s.mu.Unlock()
}

func (s *relaySet) snapshot() []*activeRelay {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*activeRelay, 0, len(s.m))
	for r := range s.m {
		out = append(out, r)
	}
	return out
}

// recheck re-routes active relays against the current state and closes the
// ones whose route changed. With onlyKillSwitch it looks only at relays that
// went direct because of the kill switch (used on health changes, so normal
// failover between group members doesn't cut working connections).
func (d *Dispatcher) recheck(onlyKillSwitch bool) {
	st := d.st.Load()
	for _, r := range d.relays.snapshot() {
		if onlyKillSwitch && !r.dec.KillSwitch {
			continue
		}
		if routeChanged(r, d.Route(r.src, r.domain, r.dstIP), st) {
			r.cut()
		}
	}
}

// cut closes both sides in the background: a Close can block (e.g. a peer
// that stopped reading), and recheck runs inside config updates, which must
// never hang.
func (r *activeRelay) cut() {
	go func() {
		r.in.Close()
		r.out.Close()
	}()
}

// routeChanged reports whether relay r must be cut under the new decision
// nd. A group relay keeps running when the group merely picks another
// member, unless its own client was edited, removed, disabled or taken out
// of the group.
func routeChanged(r *activeRelay, nd Decision, st *state) bool {
	old := r.dec
	switch {
	case old.Kind != nd.Kind, old.KillSwitch != nd.KillSwitch, old.RuleID != nd.RuleID:
		return true
	case old.Kind != KindClient:
		return false
	case old.GroupID != nd.GroupID:
		return true
	case old.GroupID == "" && old.ClientID != nd.ClientID:
		return true
	}
	// Rebuilding a client (new server, transport, UUID or private-address
	// policy) replaces its object; relays on the old one must go.
	if e := st.clients[old.ClientID]; e == nil || e.c != r.cli || !st.usable(old.ClientID) {
		return true
	}
	if old.GroupID != "" {
		g := st.groups[old.GroupID]
		if g == nil || !slices.Contains(g.g.Members, old.ClientID) {
			return true
		}
	}
	return false
}
