package dispatch

import (
	"net"
	"net/netip"
	"sync"
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
		if routeChanged(r.dec, d.Route(r.src, r.domain, r.dstIP), st) {
			r.in.Close()
			r.out.Close()
		}
	}
}

// routeChanged reports whether a relay established with old must be cut
// under the new decision nd. A group relay keeps running when the group
// merely picks another member, unless its own client became unusable.
func routeChanged(old, nd Decision, st *state) bool {
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
	return !st.usable(old.ClientID)
}
