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

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/sniff"
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
	halfOpenTimeout = 5 * time.Second // idle limit once one direction ended
)

const (
	bufSize  = 16 << 10
	sniffMax = 4 << 10 // a Chrome ClientHello with ML-KEM is ~2 KB
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, bufSize); return &b }}

// Handle serves one inbound TCP connection to dst and closes it. If
// sniffable and dst has no domain, the first client bytes are peeked for a
// TLS SNI or HTTP Host (up to sniffTimeout) and replayed to the outbound.
func (d *Dispatcher) Handle(conn net.Conn, src netip.AddrPort, dst outbound.Addr, sniffable bool) {
	defer conn.Close()
	domain := dst.Domain
	var head []byte
	if sniffable && domain == "" {
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		var err error
		head, domain, err = peek(conn, (*bp)[:sniffMax])
		if err != nil {
			return
		}
	}

	dec := d.Route(src.Addr(), domain, dst.IP)
	t := d.tracker.Open(src, dst.String(), domain, dec.RuleID, dec.ClientID, dec.GroupID)
	defer t.Close()
	if dec.Kind == KindBlock {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	out, err := d.dial(ctx, dec, domain, dst)
	cancel()
	if err != nil {
		return
	}
	defer out.Close()
	if len(head) > 0 {
		if _, err := out.Write(head); err != nil {
			return
		}
		t.AddUp(int64(len(head)))
	}
	relay(conn, out, t)
}

// peek reads client-first data into buf until a domain is found, the
// protocol is ruled out, buf is full or sniffTimeout passes. It returns
// the bytes read; err is set only when the client went away with nothing
// to forward.
func peek(conn net.Conn, buf []byte) (head []byte, domain string, err error) {
	conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	defer conn.SetReadDeadline(time.Time{})
	n := 0
	for n < len(buf) {
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
	// Copy out so the pooled buffer can be returned before the relay.
	return append([]byte(nil), buf[:n]...), domain, nil
}

// watch closes both conns when no data moved for the idle limit, which
// drops to halfOpenTimeout once one direction has finished.
type watch struct {
	a, b  net.Conn
	last  atomic.Int64 // unix nanos of the last read
	limit atomic.Int64 // nanos
	once  sync.Once

	mu    sync.Mutex
	timer *time.Timer
}

func newWatch(a, b net.Conn) *watch {
	w := &watch{a: a, b: b}
	w.touch()
	w.limit.Store(int64(idleTimeout))
	w.mu.Lock()
	w.timer = time.AfterFunc(idleTimeout, w.check)
	w.mu.Unlock()
	return w
}

func (w *watch) touch() { w.last.Store(time.Now().UnixNano()) }

func (w *watch) check() {
	left := time.Duration(w.last.Load() + w.limit.Load() - time.Now().UnixNano())
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
// closes where the conn supports CloseWrite.
func relay(client, server net.Conn, t Tracked) {
	w := newWatch(client, server)
	defer w.stop()
	done := make(chan struct{})
	go func() {
		copyHalf(server, client, w, t.AddUp)
		close(done)
	}()
	copyHalf(client, server, w, t.AddDown)
	<-done
}

func copyHalf(dst, src net.Conn, w *watch, add func(int64)) {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w.touch()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				w.abort()
				return
			}
			add(int64(n))
		}
		if err != nil {
			if err != io.EOF {
				w.abort()
				return
			}
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
			w.half()
			return
		}
	}
}
