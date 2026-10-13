package stats

import (
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/events"
)

var src = netip.MustParseAddrPort("192.168.88.10:5555")

func ticks(s *Stats, start time.Time, n int) time.Time {
	for range n {
		start = start.Add(time.Second)
		s.tick(start)
	}
	return start
}

func TestRatesAndTotals(t *testing.T) {
	s := New(nil)
	now := time.Unix(1_000_000, 0)
	s.tick(now)
	c := s.Open(src, "1.2.3.4:443", "example.com", "r1", "c1", "g1")
	c.AddUp(1000)
	c.AddDown(4000)
	now = ticks(s, now, 1)

	for _, k := range []string{"total", "client:c1", "group:g1"} {
		got := s.Traffic(k)
		want := Totals{Up: 1000, Down: 4000, UpRate: 1000, DownRate: 4000, Conns: 1}
		if got != want {
			t.Errorf("%s: got %+v want %+v", k, got, want)
		}
	}
	// Rate falls to zero when nothing moves; totals stay.
	ticks(s, now, 1)
	if got := s.Traffic("client:c1"); got.UpRate != 0 || got.Up != 1000 {
		t.Errorf("after idle: %+v", got)
	}
	c.Close()
	c.Close() // idempotent
	if got := s.Traffic("total").Conns; got != 0 {
		t.Errorf("conns after close = %d", got)
	}
	if got := s.Traffic("client:nope"); got != (Totals{}) {
		t.Errorf("unknown target: %+v", got)
	}
}

func TestDirect(t *testing.T) {
	s := New(nil)
	s.Open(src, "1.1.1.1:53", "", "r", "", "").AddUp(10)
	if got := s.Traffic("client:" + Direct).Up; got != 10 {
		t.Fatalf("direct up = %d", got)
	}
}

func TestSecondRingWrap(t *testing.T) {
	s := New(nil)
	now := time.Unix(2_000_000, 0)
	s.tick(now)
	c := s.Open(src, "d", "", "r", "c1", "")
	// 150 samples: sample i carries i bytes up.
	for i := 1; i <= 150; i++ {
		c.AddUp(int64(i))
		now = now.Add(time.Second)
		s.tick(now)
	}
	sr, err := s.Series("client:c1", "1m")
	if err != nil {
		t.Fatal(err)
	}
	if len(sr.T) != 60 || len(sr.Up) != 60 || len(sr.Delay) != 60 {
		t.Fatalf("lengths %d %d %d", len(sr.T), len(sr.Up), len(sr.Delay))
	}
	for i := range 60 {
		if want := float64(91 + i); sr.Up[i] != want {
			t.Fatalf("Up[%d] = %v want %v", i, sr.Up[i], want)
		}
		if want := now.Unix() - int64(59-i); sr.T[i] != want {
			t.Fatalf("T[%d] = %d want %d", i, sr.T[i], want)
		}
	}
}

func TestMinuteRing(t *testing.T) {
	s := New(nil)
	now := time.Unix(3_000_000, 0)
	s.tick(now) // first sample of minute 0
	c := s.Open(src, "d", "", "r", "c1", "")
	now = ticks(s, now, 59) // minute 0 closed with zero traffic
	// Minute 1: 60 B/s up.
	for range 60 {
		c.AddUp(60)
		now = now.Add(time.Second)
		s.tick(now)
	}
	sr, _ := s.Series("total", "1h")
	if len(sr.T) != 60 {
		t.Fatalf("len %d", len(sr.T))
	}
	if sr.Up[59] != 60 || sr.Up[58] != 0 {
		t.Fatalf("minute avg: %v %v", sr.Up[58], sr.Up[59])
	}
	if sr.T[59] != now.Unix() || sr.T[58] != now.Unix()-60 {
		t.Fatalf("minute timestamps %d %d (now %d)", sr.T[58], sr.T[59], now.Unix())
	}
	day, _ := s.Series("total", "24h")
	if len(day.T) != 1440 || day.Up[1439] != 60 {
		t.Fatalf("24h: len %d last %v", len(day.T), day.Up[1439])
	}
	// Wrap the minute ring fully: the 60 B/s minute must fall out.
	ticks(s, now, 1440*60)
	day, _ = s.Series("total", "24h")
	for i, v := range day.Up {
		if v != 0 {
			t.Fatalf("after wrap Up[%d] = %v", i, v)
		}
	}
}

func TestDelay(t *testing.T) {
	s := New(nil)
	now := time.Unix(4_000_000, 0)
	s.RecordDelay("c1", 123)
	now = ticks(s, now, 60)
	s.RecordDelay("c1", -1)
	now = ticks(s, now, 60)
	sr, _ := s.Series("client:c1", "1h")
	if sr.Delay[58] == nil || *sr.Delay[58] != 123 {
		t.Fatalf("delay[58] = %v", sr.Delay[58])
	}
	if sr.Delay[59] != nil {
		t.Fatalf("down minute should be nil, got %v", *sr.Delay[59])
	}
	if sr.Delay[0] != nil {
		t.Fatal("no-data minute should be nil")
	}
	s.RecordDelay("c1", 50)
	ticks(s, now, 1)
	m, _ := s.Series("client:c1", "1m")
	if m.Delay[59] == nil || *m.Delay[59] != 50 {
		t.Fatalf("1m delay = %v", m.Delay[59])
	}
	if tot, _ := s.Series("total", "1m"); tot.Delay[59] != nil {
		t.Fatal("total has no delay")
	}
}

func TestSeriesErrors(t *testing.T) {
	s := New(nil)
	if _, err := s.Series("total", "5m"); err != ErrRange {
		t.Errorf("range err = %v", err)
	}
	if _, err := s.Series("bogus", "1m"); err != ErrTarget {
		t.Errorf("target err = %v", err)
	}
	if sr, err := s.Series("group:none", "24h"); err != nil || len(sr.Up) != 1440 {
		t.Errorf("unknown group: %v %d", err, len(sr.Up))
	}
}

func TestForget(t *testing.T) {
	s := New(nil)
	c := s.Open(src, "d", "", "r", "c1", "")
	c.AddUp(5)
	s.Forget("client:c1")
	if got := s.Traffic("client:c1"); got != (Totals{}) {
		t.Fatalf("after forget: %+v", got)
	}
	c.AddUp(5) // still safe
	c.Close()
	if got := s.Traffic("total"); got.Up != 10 || got.Conns != 0 {
		t.Fatalf("total %+v", got)
	}
}

func TestConnections(t *testing.T) {
	s := New(nil)
	a := s.Open(src, "1.2.3.4:443", "a.com", "r1", "c1", "g1")
	b := s.Open(src, "5.6.7.8:80", "", "r2", "", "")
	a.AddDown(7)
	cs := s.Connections()
	if len(cs) != 2 {
		t.Fatalf("len %d", len(cs))
	}
	for _, ci := range cs {
		if ci.Domain == "a.com" {
			if ci.Down != 7 || ci.Client != "c1" || ci.Group != "g1" || ci.Src != src.String() || ci.Rule != "r1" {
				t.Errorf("row %+v", ci)
			}
			if _, err := time.Parse(time.RFC3339, ci.Start); err != nil {
				t.Errorf("start: %v", err)
			}
		} else if ci.Client != Direct {
			t.Errorf("direct row %+v", ci)
		}
	}
	js, _ := json.Marshal(cs[0])
	var m map[string]any
	json.Unmarshal(js, &m)
	for _, k := range []string{"id", "src", "dst", "domain", "rule", "client", "group", "up", "down", "start"} {
		if _, ok := m[k]; !ok {
			t.Errorf("json missing %q", k)
		}
	}
	a.Close()
	b.Close()
	if len(s.Connections()) != 0 {
		t.Fatal("table not empty")
	}
}

func TestConcurrent(t *testing.T) {
	s := New(events.New())
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		now := time.Now()
		for {
			select {
			case <-stop:
				close(done)
				return
			default:
				now = now.Add(time.Second)
				s.tick(now)
				s.Series("client:c1", "1m")
				s.Connections()
			}
		}
	}()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 200 {
				c := s.Open(src, "d", "", "r", "c1", "g1")
				c.AddUp(1)
				c.AddDown(2)
				go c.Close()
				c.Close()
			}
		})
	}
	wg.Wait()
	close(stop)
	<-done
	got := s.Traffic("group:g1")
	if got.Up != 3200 || got.Down != 6400 || got.Conns != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestEvent(t *testing.T) {
	bus := events.New()
	ch, cancel := bus.Subscribe()
	defer cancel()
	s := New(bus)
	now := time.Unix(5_000_000, 0)
	s.tick(now)
	<-ch
	c := s.Open(src, "d", "", "r", "c1", "")
	c.AddDown(100)
	s.tick(now.Add(time.Second))
	e := <-ch
	if e.Type != events.Traffic {
		t.Fatalf("type %q", e.Type)
	}
	js, _ := json.Marshal(e.Data)
	want := `{"t":5000001,"total":{"upRate":0,"downRate":100},"clients":{"c1":{"upRate":0,"downRate":100,"conns":1}}}`
	if string(js) != want {
		t.Fatalf("got  %s\nwant %s", js, want)
	}
}

// Round 15: every checked client got a 1440-point delay ring on its first
// result, even one that never answered (5.76 KB each, 1000 from one
// subscription), and a result or connection arriving after a client was
// removed recreated its counters for good.
func TestDeadClientsKeepNoDelayRingAndRetain(t *testing.T) {
	s := New(nil)
	s.RecordDelay("dead", -1)
	if tg := s.get("client:dead"); tg.delay != nil {
		t.Fatal("a client that never answered has a delay ring")
	}
	s.RecordDelay("gone", 20)
	s.Open(src, "d", "", "r", "kept", "g-gone").Close()
	s.Open(src, "d", "", "r", "", "g-kept").Close()
	s.Retain(func(key string) bool {
		return key == "client:kept" || key == "client:"+Direct || key == "group:g-kept"
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.targets) != 3 || s.targets["client:kept"] == nil || s.targets["client:"+Direct] == nil || s.targets["group:g-kept"] == nil {
		t.Fatalf("targets after Retain: %d", len(s.targets))
	}
}

// Round 16: the history rings of a client were kept until it was removed,
// so a subscription whose 1000 clients each carried traffic once pinned
// about 18 MB. A ring with a whole day of nothing is released.
func TestQuietRingsAreReleased(t *testing.T) {
	s := New(nil)
	now := time.Unix(5_000_000, 0)
	s.tick(now)
	c := s.Open(src, "d", "", "r", "c1", "")
	c.AddUp(1000)
	s.RecordDelay("c1", 20)
	now = ticks(s, now, 60)
	c.Close()
	tg := s.get("client:c1")
	if tg.r == nil || tg.delay == nil {
		t.Fatal("rings not allocated")
	}
	s.RecordDelay("c1", -1)
	now = ticks(s, now, 60*(minPoints-2))
	if tg.r == nil || tg.delay == nil {
		t.Fatal("rings released while they still hold samples of the last 24 h")
	}
	ticks(s, now, 60*(delayStale+3))
	if tg.r != nil || tg.delay != nil {
		t.Fatalf("rings kept after a day of nothing: traffic %v delay %v", tg.r != nil, tg.delay != nil)
	}
	if sr, err := s.Series("client:c1", "24h"); err != nil || len(sr.Up) != minPoints {
		t.Fatalf("series after release: %v", err)
	}
}
