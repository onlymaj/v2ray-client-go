// Package group picks a member client for each connection according to a
// group strategy, using health-check results fed in by the caller.
//
// Strategies:
//   - failover:    Members are in priority order. The current member is kept
//     while it is up; if it goes down the highest-priority up member takes
//     over at once. A higher-priority member takes back over only after it
//     reported up for 3 consecutive checks.
//   - least-ping:  The current member is replaced by a candidate only when
//     the candidate is faster by more than max(20ms, 15% of current delay)
//     on 2 consecutive updates of that candidate. If the current member
//     goes down, the fastest up member takes over at once.
//   - round-robin: Pick cycles over the up members.
//   - sticky:      Pick hashes the source address (and the destination if
//     StickyIncludeDest) with rendezvous hashing over the up members, so a
//     flow keeps its member and membership changes move only a few flows.
//
// Members that have not reported yet count as down.
package group

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type Strategy string

const (
	Failover   Strategy = "failover"
	LeastPing  Strategy = "least-ping"
	RoundRobin Strategy = "round-robin"
	Sticky     Strategy = "sticky"
)

type Group struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Strategy          Strategy `json:"strategy"`
	Members           []string `json:"members"` // client IDs; order is failover priority
	StickyIncludeDest bool     `json:"stickyIncludeDest,omitempty"`
}

const (
	failbackChecks = 3
	betterUpdates  = 2
	minImprovement = 20 * time.Millisecond
	relImprovement = 0.15
)

// MemberStatus is a snapshot of one member's health for the UI.
type MemberStatus struct {
	ID    string        `json:"id"`
	Up    bool          `json:"up"`
	Delay time.Duration `json:"delay"`
}

type member struct {
	id       string
	seed     uint64 // fnv of id, for rendezvous hashing
	up       bool
	delay    time.Duration
	seen     bool // has reported at least once
	upStreak int  // consecutive up reports (failover)
	better   int  // consecutive "better than current" reports (least-ping)
}

// Selector is safe for concurrent use.
type Selector struct {
	g        Group
	onChange func(from, to string)

	mu      sync.Mutex
	members []member
	index   map[string]int
	cur     int // index into members, -1 if none
	rr      int
}

// New builds a Selector. onChange (may be nil) is called, outside the lock,
// whenever the current member of a failover or least-ping group changes;
// to is "" when no member is up.
func New(g Group, onChange func(from, to string)) (*Selector, error) {
	switch g.Strategy {
	case Failover, LeastPing, RoundRobin, Sticky:
	default:
		return nil, fmt.Errorf("group %q: unknown strategy %q", g.ID, g.Strategy)
	}
	if len(g.Members) == 0 {
		return nil, fmt.Errorf("group %q: no members", g.ID)
	}
	s := &Selector{g: g, onChange: onChange, index: make(map[string]int, len(g.Members)), cur: -1}
	for _, id := range g.Members {
		if _, dup := s.index[id]; dup {
			return nil, fmt.Errorf("group %q: duplicate member %q", g.ID, id)
		}
		s.index[id] = len(s.members)
		s.members = append(s.members, member{id: id, seed: fnvString(offset64, id)})
	}
	s.g.Members = append([]string(nil), g.Members...)
	return s, nil
}

func (s *Selector) Group() Group { return s.g }

// Update records a health-check result for a member. Unknown IDs are ignored.
func (s *Selector) Update(id string, up bool, delay time.Duration) {
	s.mu.Lock()
	i, ok := s.index[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	m := &s.members[i]
	m.up, m.delay, m.seen = up, delay, true
	if up {
		m.upStreak++
	} else {
		m.upStreak, m.better = 0, 0
	}
	from := s.cur
	switch s.g.Strategy {
	case Failover:
		s.updateFailover(i)
	case LeastPing:
		s.updateLeastPing(i)
	}
	to := s.cur
	s.mu.Unlock()
	if from != to && s.onChange != nil {
		s.onChange(s.name(from), s.name(to))
	}
}

func (s *Selector) updateFailover(i int) {
	switch {
	case s.cur < 0 || !s.members[s.cur].up:
		s.cur = s.firstUp()
	case i < s.cur && s.members[i].upStreak >= failbackChecks:
		s.cur = i
	}
}

func (s *Selector) updateLeastPing(i int) {
	if s.cur < 0 || !s.members[s.cur].up {
		s.cur = s.fastestUp()
		s.resetBetter()
		return
	}
	m := &s.members[i]
	if i == s.cur || !m.up {
		return
	}
	cd := s.members[s.cur].delay
	margin := max(minImprovement, time.Duration(float64(cd)*relImprovement))
	if cd-m.delay > margin {
		m.better++
	} else {
		m.better = 0
	}
	if m.better >= betterUpdates {
		s.cur = i
		s.resetBetter()
	}
}

func (s *Selector) firstUp() int {
	for i := range s.members {
		if s.members[i].up {
			return i
		}
	}
	return -1
}

func (s *Selector) fastestUp() int {
	best := -1
	for i := range s.members {
		if s.members[i].up && (best < 0 || s.members[i].delay < s.members[best].delay) {
			best = i
		}
	}
	return best
}

func (s *Selector) resetBetter() {
	for i := range s.members {
		s.members[i].better = 0
	}
}

func (s *Selector) name(i int) string {
	if i < 0 {
		return ""
	}
	return s.members[i].id
}

// Pick returns the member to use for a connection from src to dst (a domain
// or IP string; only used by sticky with StickyIncludeDest). ok is false
// when no member is up, so the caller can apply its kill switch.
func (s *Selector) Pick(src netip.Addr, dst string) (string, bool) {
	return s.pick(src, dst, true)
}

// Peek returns what Pick would return next, without moving a round-robin
// group on to its next member.
func (s *Selector) Peek(src netip.Addr, dst string) (string, bool) {
	return s.pick(src, dst, false)
}

func (s *Selector) pick(src netip.Addr, dst string, advance bool) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.g.Strategy {
	case RoundRobin:
		n := len(s.members)
		for k := 0; k < n; k++ {
			i := (s.rr + k) % n
			if s.members[i].up {
				if advance {
					s.rr = i + 1
				}
				return s.members[i].id, true
			}
		}
		return "", false
	case Sticky:
		h := uint64(offset64)
		if src.IsValid() {
			a := src.As16()
			h = fnvBytes(h, a[:])
		}
		if s.g.StickyIncludeDest {
			h = fnvString(h^0xff, dst)
		}
		best, bestW := -1, uint64(0)
		for i := range s.members {
			if !s.members[i].up {
				continue
			}
			if w := mix(h ^ s.members[i].seed); best < 0 || w > bestW {
				best, bestW = i, w
			}
		}
		if best < 0 {
			return "", false
		}
		return s.members[best].id, true
	}
	if s.cur < 0 {
		return "", false
	}
	return s.members[s.cur].id, true
}

// Current returns the active member of a failover or least-ping group ("" if
// none is up). For round-robin and sticky it returns "".
// Unknown reports whether some member has not reported its health yet
// (right after start, or a client that was just added or enabled). The
// caller reports members that can never be used as down, so they do not
// keep a group unknown.
func (s *Selector) Unknown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.members {
		if !s.members[i].seen {
			return true
		}
	}
	return false
}

func (s *Selector) Current() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name(s.cur)
}

// Status returns every member's last reported health, in member order.
func (s *Selector) Status() []MemberStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]MemberStatus, len(s.members))
	for i, m := range s.members {
		out[i] = MemberStatus{ID: m.id, Up: m.up, Delay: m.delay}
	}
	return out
}

const (
	offset64 = 14695981039346656037
	prime64  = 1099511628211
)

func fnvString(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}

func fnvBytes(h uint64, b []byte) uint64 {
	for _, c := range b {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}

// mix is the splitmix64 finalizer; it spreads the combined hash so that
// rendezvous weights are independent per member.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}
