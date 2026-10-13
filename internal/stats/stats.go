// Package stats counts proxied bytes and connections per client, per group
// and in total, samples rates once a second into small in-RAM rings (60 x 1s
// and 1440 x 1min), keeps a per-client delay ring fed by health checks, and
// publishes an events.Traffic event every second.
//
// Wiring: dispatch defines its own tracker interface with the same method
// set as Tracked. Because Open returns stats.Tracked (not dispatch.Tracked),
// *Stats does not satisfy that interface directly; adapt it with
//
//	type statsTracker struct{ *stats.Stats }
//	func (t statsTracker) Open(src netip.AddrPort, dst, domain, rule, client, group string) dispatch.Tracked {
//		return t.Stats.Open(src, dst, domain, rule, client, group)
//	}
package stats

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/events"
)

// Direct is the client ID that direct (unproxied) traffic is counted under.
// Open maps an empty clientID to it as well.
const Direct = "direct"

const (
	secPoints = 60   // 1m range, 1s resolution
	minPoints = 1440 // 24h range, 1min resolution
	hourPts   = 60   // 1h range, the last 60 minute points
	// delayStale is how many minutes a delay sample is carried forward into
	// later minute slots when no newer check arrives.
	delayStale = 5
)

// Tracked is one tracked connection. It has the same method set as the
// dispatch tracker's connection type.
type Tracked interface {
	AddUp(n int64)
	AddDown(n int64)
	Close()
}

// rings holds the sampled history of one target; allocated lazily.
type rings struct {
	secUp, secDown [secPoints]float32
	minUp, minDown [minPoints]float32
}

type target struct {
	up, down, conns atomic.Int64

	// Guarded by Stats.mu.
	lastUp, lastDown int64
	upRate, downRate float64
	accUp, accDown   float64 // sum of 1s rates in the current minute
	r                *rings
	delay            *[minPoints]float32 // NaN = no data
	curDelay         float32             // latest sample, NaN when down/none
	curDelayAge      int                 // minutes since curDelay was recorded
	hasDelay         bool
	// Minutes in a row with no traffic, and with no delay sample. After a
	// whole ring of them the ring holds nothing and is released: a
	// subscription can make each of its clients carry traffic once.
	quiet, delayQuiet int
}

// Stats is safe for concurrent use.
type Stats struct {
	bus   *events.Bus
	total *target

	mu       sync.Mutex
	targets  map[string]*target // "client:<id>", "group:<id>"
	secHead  int                // next slot in sec rings
	minHead  int                // next slot in min rings
	secCount int                // samples in the current minute
	lastSec  int64              // unix time of the newest 1s sample
	lastMin  int64              // unix time of the newest 1min sample
	lastTick time.Time

	connMu sync.Mutex
	conns  map[uint64]*Conn
	nextID atomic.Uint64
}

// New returns a Stats; bus may be nil.
func New(bus *events.Bus) *Stats {
	now := time.Now().Unix()
	return &Stats{
		bus:     bus,
		total:   &target{},
		targets: map[string]*target{},
		conns:   map[uint64]*Conn{},
		lastSec: now,
		lastMin: now,
	}
}

func (s *Stats) get(key string) *target {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(key)
}

func (s *Stats) getLocked(key string) *target {
	if key == "total" {
		return s.total
	}
	t := s.targets[key]
	if t == nil {
		t = &target{curDelay: float32(math.NaN())}
		s.targets[key] = t
	}
	return t
}

// Forget drops a target's counters and history, e.g. "client:<id>" when a
// client is deleted. Open connections keep counting into the old object,
// which is no longer reported.
func (s *Stats) Forget(key string) {
	s.mu.Lock()
	delete(s.targets, key)
	s.mu.Unlock()
}

// Retain drops every target for which keep reports false.
func (s *Stats) Retain(keep func(key string) bool) {
	s.mu.Lock()
	for key := range s.targets {
		if !keep(key) {
			delete(s.targets, key)
		}
	}
	s.mu.Unlock()
}

// Conn is a tracked connection.
type Conn struct {
	s       *Stats
	id      uint64
	src     netip.AddrPort
	dst     string
	domain  string
	rule    string
	client  string
	group   string
	start   time.Time
	up      atomic.Int64
	down    atomic.Int64
	closed  atomic.Bool
	tClient *target
	tGroup  *target // nil when not routed through a group
}

// Open registers a new connection. An empty clientID means direct.
func (s *Stats) Open(src netip.AddrPort, dst, domain, ruleID, clientID, groupID string) Tracked {
	if clientID == "" {
		clientID = Direct
	}
	c := &Conn{
		s: s, id: s.nextID.Add(1), src: src, dst: dst, domain: domain,
		rule: ruleID, client: clientID, group: groupID, start: time.Now(),
	}
	s.mu.Lock()
	c.tClient = s.getLocked("client:" + clientID)
	if groupID != "" {
		c.tGroup = s.getLocked("group:" + groupID)
	}
	s.mu.Unlock()
	s.total.conns.Add(1)
	c.tClient.conns.Add(1)
	if c.tGroup != nil {
		c.tGroup.conns.Add(1)
	}
	s.connMu.Lock()
	s.conns[c.id] = c
	s.connMu.Unlock()
	return c
}

func (c *Conn) AddUp(n int64) {
	c.up.Add(n)
	c.s.total.up.Add(n)
	c.tClient.up.Add(n)
	if c.tGroup != nil {
		c.tGroup.up.Add(n)
	}
}

func (c *Conn) AddDown(n int64) {
	c.down.Add(n)
	c.s.total.down.Add(n)
	c.tClient.down.Add(n)
	if c.tGroup != nil {
		c.tGroup.down.Add(n)
	}
}

// Close is idempotent.
func (c *Conn) Close() {
	if c.closed.Swap(true) {
		return
	}
	c.s.total.conns.Add(-1)
	c.tClient.conns.Add(-1)
	if c.tGroup != nil {
		c.tGroup.conns.Add(-1)
	}
	c.s.connMu.Lock()
	delete(c.s.conns, c.id)
	c.s.connMu.Unlock()
}

// ConnInfo is one row of the live connection table.
type ConnInfo struct {
	ID     uint64 `json:"id"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Domain string `json:"domain"`
	Rule   string `json:"rule"`
	Client string `json:"client"`
	Group  string `json:"group"`
	Up     int64  `json:"up"`
	Down   int64  `json:"down"`
	Start  string `json:"start"` // RFC3339
}

// Connections returns a snapshot of the open connections.
func (s *Stats) Connections() []ConnInfo {
	s.connMu.Lock()
	out := make([]ConnInfo, 0, len(s.conns))
	for _, c := range s.conns {
		out = append(out, ConnInfo{
			ID: c.id, Src: c.src.String(), Dst: c.dst, Domain: c.domain,
			Rule: c.rule, Client: c.client, Group: c.group,
			Up: c.up.Load(), Down: c.down.Load(),
			Start: c.start.UTC().Format(time.RFC3339),
		})
	}
	s.connMu.Unlock()
	return out
}

// Totals are the current counters of one target.
type Totals struct {
	Up       int64   `json:"up"`
	Down     int64   `json:"down"`
	UpRate   float64 `json:"upRate"`   // bytes/s over the last second
	DownRate float64 `json:"downRate"` // bytes/s over the last second
	Conns    int64   `json:"conns"`
}

// Traffic returns the totals for "total", "client:<id>" or "group:<id>".
// Unknown targets return zeros.
func (s *Stats) Traffic(key string) Totals {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.total
	if key != "total" {
		if t = s.targets[key]; t == nil {
			return Totals{}
		}
	}
	return Totals{
		Up: t.up.Load(), Down: t.down.Load(),
		UpRate: t.upRate, DownRate: t.downRate, Conns: t.conns.Load(),
	}
}

// RecordDelay stores a health-check result for a client; ms < 0 means down.
func (s *Stats) RecordDelay(clientID string, ms float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.getLocked("client:" + clientID)
	if t.delay == nil {
		if ms < 0 {
			// No history to keep for a client that has never answered:
			// a subscription can hold a thousand dead servers.
			return
		}
		t.delay = new([minPoints]float32)
		for i := range t.delay {
			t.delay[i] = float32(math.NaN())
		}
	}
	if ms < 0 {
		t.curDelay = float32(math.NaN())
	} else {
		t.curDelay = float32(ms)
	}
	t.curDelayAge = 0
	t.hasDelay = true
}

// Run samples every second until ctx is done.
func (s *Stats) Run(ctx context.Context) {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tk.C:
			s.tick(now)
		}
	}
}

// tick takes one 1s sample; every 60th sample also closes a minute.
func (s *Stats) tick(now time.Time) {
	s.mu.Lock()
	dt := 1.0
	if !s.lastTick.IsZero() {
		if d := now.Sub(s.lastTick).Seconds(); d > 0.2 {
			dt = d
		}
	}
	s.lastTick = now
	s.lastSec = now.Unix()
	s.secCount++
	closeMin := s.secCount >= 60
	s.sample(s.total, dt, closeMin)
	for _, t := range s.targets {
		s.sample(t, dt, closeMin)
	}
	s.secHead = (s.secHead + 1) % secPoints
	if closeMin {
		s.secCount = 0
		s.minHead = (s.minHead + 1) % minPoints
		s.lastMin = s.lastSec
	}
	var ev *trafficEvent
	if s.bus != nil {
		ev = s.buildEvent()
	}
	s.mu.Unlock()
	if ev != nil {
		s.bus.Publish(events.Event{Type: events.Traffic, Data: ev})
	}
}

func (s *Stats) sample(t *target, dt float64, closeMin bool) {
	up, down := t.up.Load(), t.down.Load()
	t.upRate = float64(up-t.lastUp) / dt
	t.downRate = float64(down-t.lastDown) / dt
	t.lastUp, t.lastDown = up, down
	if t.r == nil && (t.upRate != 0 || t.downRate != 0) {
		t.r = new(rings)
	}
	if t.r != nil {
		t.r.secUp[s.secHead] = float32(t.upRate)
		t.r.secDown[s.secHead] = float32(t.downRate)
		t.accUp += t.upRate
		t.accDown += t.downRate
	}
	if !closeMin {
		return
	}
	if t.r != nil {
		n := float64(s.secCount)
		t.r.minUp[s.minHead] = float32(t.accUp / n)
		t.r.minDown[s.minHead] = float32(t.accDown / n)
		if t.accUp != 0 || t.accDown != 0 {
			t.quiet = 0
		} else if t.quiet++; t.quiet >= minPoints {
			t.r, t.quiet = nil, 0
		}
	}
	t.accUp, t.accDown = 0, 0
	if t.delay != nil {
		v := float32(math.NaN())
		if t.hasDelay && t.curDelayAge < delayStale {
			v = t.curDelay
		}
		t.delay[s.minHead] = v
		t.curDelayAge++
		if v == v { // not NaN
			t.delayQuiet = 0
		} else if t.delayQuiet++; t.delayQuiet >= minPoints {
			t.delay, t.delayQuiet = nil, 0
		}
	}
}

type rateJSON struct {
	UpRate   float64 `json:"upRate"`
	DownRate float64 `json:"downRate"`
}

type clientRateJSON struct {
	UpRate   float64 `json:"upRate"`
	DownRate float64 `json:"downRate"`
	Conns    int64   `json:"conns"`
}

type trafficEvent struct {
	T       int64                     `json:"t"`
	Total   rateJSON                  `json:"total"`
	Clients map[string]clientRateJSON `json:"clients"`
}

func (s *Stats) buildEvent() *trafficEvent {
	ev := &trafficEvent{
		T:       s.lastSec,
		Total:   rateJSON{s.total.upRate, s.total.downRate},
		Clients: make(map[string]clientRateJSON),
	}
	for k, t := range s.targets {
		if id, ok := strings.CutPrefix(k, "client:"); ok {
			ev.Clients[id] = clientRateJSON{t.upRate, t.downRate, t.conns.Load()}
		}
	}
	return ev
}

// Series is a chart-ready history. Delay is only filled for client targets;
// a nil entry means no data (no check, or the client was down).
type Series struct {
	T     []int64    `json:"t"` // unix seconds
	Up    []float64  `json:"up"`
	Down  []float64  `json:"down"`
	Delay []*float64 `json:"delay"`
}

var (
	ErrRange  = errors.New("stats: range must be 1m, 1h or 24h")
	ErrTarget = errors.New("stats: target must be total, client:<id> or group:<id>")
)

// Series returns the history of target ("total" | "client:<id>" |
// "group:<id>") for rng "1m" (60 x 1s), "1h" (60 x 1min) or "24h"
// (1440 x 1min), oldest first. Unknown IDs return zeros.
func (s *Stats) Series(key, rng string) (Series, error) {
	if key != "total" && !strings.HasPrefix(key, "client:") && !strings.HasPrefix(key, "group:") {
		return Series{}, ErrTarget
	}
	var n, step int
	switch rng {
	case "1m":
		n, step = secPoints, 1
	case "1h":
		n, step = hourPts, 60
	case "24h":
		n, step = minPoints, 60
	default:
		return Series{}, ErrRange
	}
	out := Series{T: make([]int64, n), Up: make([]float64, n), Down: make([]float64, n), Delay: make([]*float64, n)}

	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.total
	if key != "total" {
		t = s.targets[key] // may be nil
	}
	last, head, size := s.lastMin, s.minHead, minPoints
	if step == 1 {
		last, head, size = s.lastSec, s.secHead, secPoints
	}
	for i := range n {
		out.T[i] = last - int64((n-1-i)*step)
		// head is the next slot to write, so head-1 is the newest.
		idx := ((head-n+i)%size + size) % size
		if t == nil {
			continue
		}
		if t.r != nil {
			if step == 1 {
				out.Up[i], out.Down[i] = float64(t.r.secUp[idx]), float64(t.r.secDown[idx])
			} else {
				out.Up[i], out.Down[i] = float64(t.r.minUp[idx]), float64(t.r.minDown[idx])
			}
		}
		if t.delay == nil {
			continue
		}
		var v float32
		if step == 1 {
			// No per-second delay history: show the latest sample.
			if !t.hasDelay || t.curDelayAge >= delayStale {
				continue
			}
			v = t.curDelay
		} else {
			v = t.delay[idx]
		}
		if !math.IsNaN(float64(v)) {
			f := float64(v)
			out.Delay[i] = &f
		}
	}
	return out, nil
}
