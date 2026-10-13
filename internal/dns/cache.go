package dns

import (
	"container/list"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

const (
	minTTL         = 5 * time.Second
	maxTTL         = time.Hour
	maxNegativeTTL = 5 * time.Minute
	// maxCachedResp is the largest response kept. Upstream answers arrive
	// over TCP and can be 64 KB; a LAN device asking for 1024 such names
	// would otherwise pin 64 MB.
	maxCachedResp = 4096
	// maxCachedRRs is the most records a kept response may have.
	maxCachedRRs = 64
)

type cacheKey struct {
	name  string // lowercased
	qtype uint16
	class uint16
	route string // Options.RouteKey result; "" in keyOf
}

type cacheEntry struct {
	key     cacheKey
	resp    []byte
	ttlOffs []int // offsets of TTL fields to decrement (OPT excluded)
	qEnd    int   // end of resp's question section
	stored  time.Time
	expires time.Time
}

// cache is an LRU of raw upstream responses.
type cache struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[cacheKey]*list.Element
	now func() time.Time
}

func newCache(size int) *cache {
	return &cache{max: size, ll: list.New(), m: map[cacheKey]*list.Element{}, now: time.Now}
}

func keyOf(q question) cacheKey {
	return cacheKey{name: strings.ToLower(q.Name), qtype: q.Type, class: q.Class}
}

// get returns a copy of the cached response for query with its ID and
// question bytes taken from query and TTLs decremented by the time spent
// in the cache, or nil. Entries are kept per route.
func (c *cache) get(query []byte, q question, route string) []byte {
	k := keyOf(q)
	k.route = route
	c.mu.Lock()
	el, ok := c.m[k]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	e := el.Value.(*cacheEntry)
	now := c.now()
	if !now.Before(e.expires) {
		c.ll.Remove(el)
		delete(c.m, k)
		c.mu.Unlock()
		return nil
	}
	c.ll.MoveToFront(el)
	resp := append([]byte(nil), e.resp...)
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	c.mu.Unlock()

	copy(resp[0:2], query[0:2])
	// Echo the client's question spelling (DNS 0x20 case randomisation).
	if q.End == e.qEnd {
		copy(resp[headerLen:q.End], query[headerLen:q.End])
	}
	for _, off := range e.ttlOffs {
		ttl := binary.BigEndian.Uint32(resp[off:])
		binary.BigEndian.PutUint32(resp[off:], ttl-min(ttl, elapsed))
	}
	return resp
}

// put stores resp if it is cacheable: NOERROR or NXDOMAIN, not truncated.
// Positive answers live for the minimum record TTL; negative ones (no
// answers) for the SOA minimum, capped at 5 minutes.
func (c *cache) put(q question, route string, resp []byte) {
	h, rq, err := parseQuestion(resp)
	if err != nil || len(resp) > maxCachedResp || h.Flags&flagTC != 0 || keyOf(rq) != keyOf(q) {
		return
	}
	rc := h.rcode()
	if rc != rcodeNoError && rc != rcodeNXDomain {
		return
	}
	rrs, err := parseRecords(resp, h, rq.End)
	// An answer made of the smallest records cost twice its size again in
	// TTL offsets, 8 MiB for a full cache (round 21).
	if err != nil || len(rrs) > maxCachedRRs {
		return
	}
	var offs []int
	ttl, haveTTL := uint32(0), false
	negative := rc == rcodeNXDomain || h.ANCount == 0
	for _, r := range rrs {
		if r.Type == typeOPT {
			continue
		}
		offs = append(offs, r.TTLOff)
		var t uint32
		switch {
		case !negative && r.Section == 0:
			t = r.TTL
		case negative && r.Section == 1 && r.Type == typeSOA && r.RDLen >= 22:
			// RFC 2308: min of the SOA record TTL and its MINIMUM field,
			// the last 4 bytes of the RDATA.
			t = min(r.TTL, binary.BigEndian.Uint32(resp[r.RDataOff+r.RDLen-4:]))
		default:
			continue
		}
		if !haveTTL || t < ttl {
			ttl, haveTTL = t, true
		}
	}
	if !haveTTL {
		return // e.g. NODATA without SOA
	}
	d := time.Duration(ttl) * time.Second
	if negative {
		d = min(d, maxNegativeTTL)
	}
	d = max(minTTL, min(d, maxTTL))

	now := c.now()
	k := keyOf(q)
	k.route = route
	e := &cacheEntry{key: k, resp: append([]byte(nil), resp...), ttlOffs: offs, qEnd: rq.End, stored: now, expires: now.Add(d)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[e.key]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
		return
	}
	c.m[e.key] = c.ll.PushFront(e)
	for c.ll.Len() > c.max {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.m, old.Value.(*cacheEntry).key)
	}
}

func (c *cache) flush() {
	c.mu.Lock()
	c.ll.Init()
	clear(c.m)
	c.mu.Unlock()
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
