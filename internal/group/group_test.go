package group

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

const ms = time.Millisecond

type changes struct {
	mu  sync.Mutex
	log []string
}

func (c *changes) fn(from, to string) {
	c.mu.Lock()
	c.log = append(c.log, from+">"+to)
	c.mu.Unlock()
}

func newSel(t *testing.T, strat Strategy, c *changes, members ...string) *Selector {
	t.Helper()
	var cb func(string, string)
	if c != nil {
		cb = c.fn
	}
	s, err := New(Group{ID: "g", Strategy: strat, Members: members}, cb)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wantCur(t *testing.T, s *Selector, want string) {
	t.Helper()
	got, ok := s.Pick(netip.Addr{}, "")
	if got != want || ok != (want != "") || s.Current() != want {
		t.Fatalf("Pick = %q, %v; Current = %q; want %q", got, ok, s.Current(), want)
	}
}

func TestFailover(t *testing.T) {
	var c changes
	s := newSel(t, Failover, &c, "a", "b", "c")
	wantCur(t, s, "") // nothing reported yet: kill switch

	s.Update("b", true, 50*ms)
	wantCur(t, s, "b")
	s.Update("c", true, 10*ms)
	wantCur(t, s, "b") // lower priority never preempts

	// a must be up for 3 consecutive checks before failing back.
	s.Update("a", true, 80*ms)
	s.Update("a", true, 80*ms)
	wantCur(t, s, "b")
	s.Update("a", false, 0) // flap resets the streak
	s.Update("a", true, 80*ms)
	s.Update("a", true, 80*ms)
	wantCur(t, s, "b")
	s.Update("a", true, 80*ms)
	wantCur(t, s, "a")

	// Current down: switch immediately to the best up member.
	s.Update("a", false, 0)
	wantCur(t, s, "b")
	s.Update("b", false, 0)
	wantCur(t, s, "c")
	s.Update("c", false, 0)
	wantCur(t, s, "")

	want := []string{">b", "b>a", "a>b", "b>c", "c>"}
	if fmt.Sprint(c.log) != fmt.Sprint(want) {
		t.Errorf("changes = %v, want %v", c.log, want)
	}
}

func TestLeastPing(t *testing.T) {
	var c changes
	s := newSel(t, LeastPing, &c, "a", "b", "c")
	s.Update("a", true, 100*ms)
	wantCur(t, s, "a")

	// 15ms better: below the 20ms floor, never switches.
	for range 5 {
		s.Update("b", true, 85*ms)
	}
	wantCur(t, s, "a")

	// Alternating better/worse never reaches 2 consecutive: no flapping.
	for range 5 {
		s.Update("b", true, 50*ms)
		s.Update("b", true, 95*ms)
	}
	wantCur(t, s, "a")

	// Two consecutive clearly-better updates switch.
	s.Update("b", true, 50*ms)
	wantCur(t, s, "a")
	s.Update("b", true, 50*ms)
	wantCur(t, s, "b")

	// Relative margin: current 400ms needs > 60ms improvement.
	s.Update("b", true, 400*ms)
	s.Update("a", true, 345*ms)
	s.Update("a", true, 345*ms)
	wantCur(t, s, "b")
	s.Update("a", true, 330*ms)
	s.Update("a", true, 330*ms)
	wantCur(t, s, "a")

	// Current down: fastest up member at once.
	s.Update("c", true, 200*ms)
	s.Update("b", true, 250*ms)
	s.Update("a", false, 0)
	wantCur(t, s, "c")

	want := []string{">a", "a>b", "b>a", "a>c"}
	if fmt.Sprint(c.log) != fmt.Sprint(want) {
		t.Errorf("changes = %v, want %v", c.log, want)
	}
}

func TestRoundRobin(t *testing.T) {
	s := newSel(t, RoundRobin, nil, "a", "b", "c")
	if _, ok := s.Pick(netip.Addr{}, ""); ok {
		t.Fatal("pick with no member up")
	}
	s.Update("a", true, 0)
	s.Update("c", true, 0)
	var got string
	for range 4 {
		id, _ := s.Pick(netip.Addr{}, "")
		got += id
	}
	if got != "acac" {
		t.Errorf("sequence = %s, want acac", got)
	}
}

func TestSticky(t *testing.T) {
	members := []string{"a", "b", "c", "d"}
	s := newSel(t, Sticky, nil, members...)
	for _, m := range members {
		s.Update(m, true, 0)
	}
	srcs := make([]netip.Addr, 400)
	before := make([]string, len(srcs))
	count := map[string]int{}
	for i := range srcs {
		srcs[i] = netip.AddrFrom4([4]byte{192, 168, byte(i >> 8), byte(i)})
		before[i], _ = s.Pick(srcs[i], "x.example")
		if again, _ := s.Pick(srcs[i], "y.example"); again != before[i] {
			t.Fatalf("sticky changed with dest while StickyIncludeDest=false")
		}
		count[before[i]]++
	}
	for _, m := range members {
		if count[m] < 50 { // expect ~100 each
			t.Errorf("member %s got %d/400 flows: poor spread %v", m, count[m], count)
		}
	}
	// Removing one member only moves the flows that were on it.
	s.Update("b", false, 0)
	for i, src := range srcs {
		after, _ := s.Pick(src, "")
		if before[i] != "b" && after != before[i] {
			t.Fatalf("flow %v moved %s -> %s although its member stayed up", src, before[i], after)
		}
		if after == "b" {
			t.Fatal("picked a down member")
		}
	}

	sd, _ := New(Group{ID: "g", Strategy: Sticky, Members: members, StickyIncludeDest: true}, nil)
	for _, m := range members {
		sd.Update(m, true, 0)
	}
	seen := map[string]bool{}
	for i := range 50 {
		id, _ := sd.Pick(srcs[0], fmt.Sprintf("d%d.example", i))
		seen[id] = true
	}
	if len(seen) < 3 {
		t.Errorf("StickyIncludeDest spread over only %d members", len(seen))
	}
}

func TestNewErrors(t *testing.T) {
	for _, g := range []Group{
		{ID: "x", Strategy: "random", Members: []string{"a"}},
		{ID: "x", Strategy: Failover},
		{ID: "x", Strategy: Failover, Members: []string{"a", "a"}},
	} {
		if _, err := New(g, nil); err == nil {
			t.Errorf("New(%+v) succeeded", g)
		}
	}
}

func TestConcurrent(t *testing.T) {
	s := newSel(t, LeastPing, nil, "a", "b")
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 1000 {
				s.Update([]string{"a", "b"}[j%2], j%7 != 0, time.Duration(i*j%300)*ms)
				s.Pick(netip.AddrFrom4([4]byte{10, 0, 0, byte(j)}), "")
				s.Current()
			}
		}()
	}
	wg.Wait()
}
