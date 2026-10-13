package dispatch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/client"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/sniff"
	"github.com/onlymaj/v2ray-client-go/internal/transport"
)

// Tracker records connections for the stats/UI layer (internal/stats).
type Tracker interface {
	Open(src netip.AddrPort, dst, domain, ruleID, clientID, groupID string) Tracked
}

// Tracked is one open connection. AddUp counts client->proxy bytes, AddDown
// proxy->client bytes.
type Tracked interface {
	AddUp(n int64)
	AddDown(n int64)
	Close()
}

type nopTracker struct{}

func (nopTracker) Open(netip.AddrPort, string, string, string, string, string) Tracked {
	return nopTracker{}
}
func (nopTracker) AddUp(int64)   {}
func (nopTracker) AddDown(int64) {}
func (nopTracker) Close()        {}

var (
	// Tunables (vars so tests can shorten them).
	sniffTimeout    = 300 * time.Millisecond
	dialTimeout     = 15 * time.Second
	idleTimeout     = 5 * time.Minute
	silentTimeout   = 30 * time.Second // idle limit until the client sends a byte
	halfOpenTimeout = 5 * time.Second  // idle limit once one direction ended
)

const (
	bufSize  = 16 << 10
	sniffMax = 4 << 10 // a Chrome ClientHello with ML-KEM is ~2 KB
)

// peekPool holds the buffers of the sniff: a quarter of a copy buffer,
// held for up to the sniff timeout by a connection that sends nothing.
var peekPool = sync.Pool{New: func() any { b := make([]byte, sniffMax); return &b }}

var bufPool = sync.Pool{New: func() any { b := make([]byte, bufSize); return &b }}

// Handle serves one inbound TCP connection to dst and closes it. If
// sniffable and dst has no domain, the first client bytes are peeked for a
// TLS SNI or HTTP Host (up to sniffTimeout) and replayed to the outbound.
// Destinations in the container or on the router are refused, and a
// domain routed direct is resolved here so dest rules and the refusal
// apply to the address actually dialed.
func (d *Dispatcher) Handle(conn net.Conn, src netip.AddrPort, dst outbound.Addr, sniffable bool) {
	defer conn.Close()
	if dst.IP.IsValid() && refused(dst.IP) {
		d.tracker.Open(src, dst.String(), dst.Domain, "refused", "", "").Close()
		return
	}
	domain := dst.Domain
	var head []byte
	if sniffable && domain == "" {
		bp := peekPool.Get().(*[]byte)
		var err error
		head, domain, err = peek(conn, *bp)
		peekPool.Put(bp)
		if err != nil {
			return
		}
	}

	// The source lets a transport that shares limits between tunnels
	// charge them to this device (round 16: only DNS dials carried it).
	ctx, cancel := context.WithTimeout(transport.WithSource(context.Background(), src.Addr().String()), dialTimeout)
	defer cancel()
	dec := d.Route(src.Addr(), domain, dst.IP)
	if dec.Kind == KindDirect && !dst.IP.IsValid() {
		ip, err := resolve(ctx, dst.Domain)
		if err != nil || refused(ip) {
			d.tracker.Open(src, dst.String(), domain, "refused", "", "").Close()
			return
		}
		dst = outbound.Addr{IP: ip, Port: dst.Port} // dial what was checked
		dec = d.Route(src.Addr(), domain, ip)
	}
	t := d.tracker.Open(src, dst.String(), domain, dec.RuleID, dec.ClientID, dec.GroupID)
	defer t.Close()
	if dec.Kind == KindBlock {
		return
	}
	var cli *client.Client
	if e := d.st.Load().clients[dec.ClientID]; e != nil {
		cli = e.c
	}
	out, err := d.dial(ctx, dec, domain, dst)
	cancel()
	if err != nil {
		return
	}
	defer out.Close()
	ar := &activeRelay{src: src.Addr(), domain: domain, dstIP: dst.IP, dec: dec, cli: cli, in: conn, out: out}
	d.relays.add(ar)
	defer d.relays.remove(ar)
	// A config change during the dial ran its recheck before this relay was
	// registered; check it now against the current state.
	if routeChanged(ar, d.Preview(src.Addr(), domain, dst.IP), d.st.Load()) {
		return
	}
	if len(head) > 0 {
		if _, err := out.Write(head); err != nil {
			return
		}
		t.AddUp(int64(len(head)))
	}
	relay(conn, out, t, len(head) > 0)
}

// maxSniffReads is how many reads peek waits for a head to be complete.
const maxSniffReads = 16

// peek reads client-first data into buf until a domain is found, the
// protocol is ruled out, buf is full or sniffTimeout passes. It returns
// the bytes read; err is set only when the client went away with nothing
// to forward.
func peek(conn net.Conn, buf []byte) (head []byte, domain string, err error) {
	conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	defer conn.SetReadDeadline(time.Time{})
	n := 0
	for reads := 0; n < len(buf); reads++ {
		// Every read parses the head again from its start. A device that
		// sent an HTTP-looking head a byte per packet had it parsed 4096
		// times, CPU for next to no traffic (round 22). A real head comes
		// in a few packets.
		if reads == maxSniffReads {
			break
		}
		m, rerr := conn.Read(buf[n:])
		n += m
		if m > 0 {
			dom, _, serr := sniff.Sniff(buf[:n])
			if serr == nil {
				domain = dom
				break
			}
			if !errors.Is(serr, sniff.ErrNeedMore) {
				break
			}
		}
		if rerr != nil {
			var ne net.Error
			if n == 0 && !(errors.As(rerr, &ne) && ne.Timeout()) {
				return nil, "", rerr
			}
			break
		}
	}
	if n == 0 {
		return nil, "", nil
	}
	// A ClientHello longer than buf, or in more pieces than are waited
	// for, went unsniffed and missed its domain rule; one with a large
	// session ticket or two post-quantum key shares can be that long
	// (round 23). The name is taken if it is in what has arrived.
	if domain == "" && buf[0] == 0x16 {
		if dom, err := sniff.SNIPrefix(buf[:n]); err == nil {
			domain = dom
		}
	}
	// Copy out so the pooled buffer can be returned before the relay.
	return append([]byte(nil), buf[:n]...), domain, nil
}

// watch closes both conns when no data moved for the idle limit, which
// is silentTimeout until the client first sends, and drops to
// halfOpenTimeout once one direction has finished.
type watch struct {
	a, b   net.Conn
	last   atomic.Int64 // monoNow of the last read
	limit  atomic.Int64 // nanos
	silent atomic.Int64 // the silent limit while still in force, else 0
	once   sync.Once

	mu    sync.Mutex
	timer *time.Timer
}

func newWatch(a, b net.Conn, clientSent bool) *watch {
	w := &watch{a: a, b: b}
	w.touch()
	limit := idleTimeout
	if !clientSent {
		limit = min(silentTimeout, idleTimeout)
		w.silent.Store(int64(limit))
	}
	w.limit.Store(int64(limit))
	w.mu.Lock()
	w.timer = time.AfterFunc(limit, w.check)
	w.mu.Unlock()
	return w
}

// clientActive lifts the silent limit (but not a half-open one).
func (w *watch) clientActive() {
	if s := w.silent.Swap(0); s != 0 {
		w.limit.CompareAndSwap(s, int64(idleTimeout))
	}
}

// watchBase anchors the watchdog's clock. time.Since reads the monotonic
// clock, so a wall-clock step (the router has no battery clock and syncs
// by NTP after start) neither cuts every quiet relay nor holds the limits
// off for the size of the step.
var watchBase = time.Now()

func monoNow() int64 { return int64(time.Since(watchBase)) }

func (w *watch) touch() { w.last.Store(monoNow()) }

func (w *watch) check() {
	left := time.Duration(w.last.Load() + w.limit.Load() - monoNow())
	if left <= 0 {
		w.abort()
		return
	}
	w.reset(left)
}

func (w *watch) half() {
	w.limit.Store(int64(halfOpenTimeout))
	w.reset(halfOpenTimeout)
}

func (w *watch) reset(d time.Duration) {
	w.mu.Lock()
	w.timer.Reset(d)
	w.mu.Unlock()
}

func (w *watch) stop() {
	w.mu.Lock()
	w.timer.Stop()
	w.mu.Unlock()
}

func (w *watch) abort() {
	w.once.Do(func() {
		w.a.Close()
		w.b.Close()
	})
}

// relay copies both ways until both directions end, propagating half
// closes where the conn supports CloseWrite. clientSent tells whether the
// client already sent data (the sniffed head).
func relay(client, server net.Conn, t Tracked, clientSent bool) {
	w := newWatch(client, server, clientSent)
	defer w.stop()
	done := make(chan struct{})
	go func() {
		copyHalf(server, client, w, func(n int64) {
			w.clientActive()
			t.AddUp(n)
		})
		close(done)
	}()
	copyHalf(client, server, w, t.AddDown)
	<-done
}

// idleBuf is the buffer a relay direction waits with. The 16 KiB pooled one
// is taken only while reads fill it: held across the blocking Read, the two
// of them were 32 KiB of every idle connection, and 512 idle connections
// over TLS did not fit in the memory limit (round 20).
const idleBuf = 2048

func copyHalf(dst, src net.Conn, w *watch, add func(int64)) {
	// pass handles one Read result and reports whether the copy is over.
	pass := func(b []byte, err error) bool {
		if len(b) > 0 {
			w.touch()
			if _, werr := dst.Write(b); werr != nil {
				w.abort()
				return true
			}
			add(int64(len(b)))
		}
		if err == nil {
			return false
		}
		if err != io.EOF {
			w.abort()
			return true
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		w.half()
		return true
	}
	small := make([]byte, idleBuf)
	for {
		n, err := src.Read(small)
		if pass(small[:n], err) {
			return
		}
		if n < len(small) {
			continue
		}
		// Data is flowing: the large buffer, for as long as reads come
		// back mostly full. A read that does not has emptied the source
		// and the next one may wait. (Round 21: "at least the small
		// buffer's worth" kept the large one through the wait after almost
		// every burst. "Full" would be the strict test, but the read after
		// the small one never gets a whole TLS record, and a steady flow
		// would then use two reads and two writes for each.) What is
		// left: a burst that ends on a nearly full read waits with the
		// large buffer, and a peer can arrange that.
		bp := bufPool.Get().(*[]byte)
		for stay := len(*bp) * 3 / 4; ; {
			n, err = src.Read(*bp)
			if pass((*bp)[:n], err) {
				bufPool.Put(bp)
				return
			}
			if n < stay {
				break
			}
		}
		bufPool.Put(bp)
	}
}
