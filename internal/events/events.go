// Package events is an in-process pub/sub bus feeding the SSE endpoint.
// Slow subscribers drop events instead of blocking publishers.
package events

import "sync"

// Event types, matching the SSE event names in web/API.md.
const (
	Traffic = "traffic" // every 1s: {t, total:{upRate,downRate}, clients:{id:{upRate,downRate,conns}}}
	Ping    = "ping"    // {id, tcpMs, delayMs, state}
	Status  = "status"  // {id, state, lastError}
	Group   = "group"   // {id, current}
)

type Event struct {
	Type string
	Data any // marshalled to JSON by the SSE handler
}

type Bus struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func New() *Bus { return &Bus{subs: map[chan Event]struct{}{}} }

// Publish delivers e to every subscriber that has room in its buffer.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe returns a buffered channel and a cancel func that must be
// called when the subscriber goes away.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}
