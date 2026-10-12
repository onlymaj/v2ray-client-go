package client

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// retryLimit bounds the data kept for replay; past it the conn is
// considered in use and no longer retried.
const retryLimit = 16 << 10

// retryConn wraps a proxied conn that runs on a reused pooled transport
// conn. Until the first byte is read back it records what was written; if
// a Write fails, or the first Read fails with nothing received (the warm
// conn was dead), it dials once more without the pool, replays the
// recorded data and carries on there. VLESS/VMess send their header with
// the first Write (or before the first Read), so a dead conn surfaces here
// rather than in Dial.
//
// A failed Read or Write cannot tell a conn that was dead from one that
// delivered the earlier data and was then reset (by the server, or by an
// on-path attacker injecting a RST), so that data is replayed only if it is
// harmless: nothing, or only complete TLS handshake records (a ClientHello). Replaying a plaintext request such as an HTTP
// POST could run it twice at the destination.
type retryConn struct {
	redial func() (net.Conn, error)

	mu    sync.Mutex // held during armed Writes and the redial
	armed atomic.Bool
	sent  []byte

	// st guards cur and closed and is never held across I/O: Close and the
	// deadline setters must work while a Write is stuck holding mu, or
	// nothing could end that Write. cur changes only with mu held as well.
	st     sync.Mutex
	cur    net.Conn
	closed bool
}

func newRetryConn(c net.Conn, redial func() (net.Conn, error)) *retryConn {
	r := &retryConn{cur: c, redial: redial}
	r.armed.Store(true)
	return r
}

func (r *retryConn) conn() (net.Conn, bool) {
	r.st.Lock()
	defer r.st.Unlock()
	return r.cur, r.armed.Load()
}

// retry replaces old with a fresh conn unless that already happened. The
// caller holds r.mu.
func (r *retryConn) retryLocked(old net.Conn) error {
	if r.cur != old {
		return nil
	}
	if !r.armed.Load() {
		return net.ErrClosed
	}
	r.armed.Store(false)
	old.Close()
	r.st.Lock()
	closed := r.closed
	r.st.Unlock()
	if closed {
		return net.ErrClosed
	}
	nc, err := r.redial()
	if err != nil {
		return err
	}
	// The new conn becomes current before the replay so that Close can end
	// a replay Write that blocks.
	r.st.Lock()
	if r.closed { // closed during the redial
		r.st.Unlock()
		nc.Close()
		return net.ErrClosed
	}
	r.cur = nc
	r.st.Unlock()
	if len(r.sent) > 0 {
		if _, err := nc.Write(r.sent); err != nil {
			nc.Close()
			return err
		}
	}
	r.sent = nil
	return nil
}

func (r *retryConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	if !r.armed.Load() {
		c := r.cur
		r.mu.Unlock()
		return c.Write(p)
	}
	defer r.mu.Unlock()
	old := r.cur
	n, err := old.Write(p)
	if err == nil {
		if len(r.sent)+len(p) > retryLimit {
			r.armed.Store(false)
			r.sent = nil
		} else {
			r.sent = append(r.sent, p...)
		}
		return n, nil
	}
	if !onlyTLSHandshake(r.sent) {
		r.armed.Store(false)
		r.sent = nil
		return n, err
	}
	if r.retryLocked(old) != nil {
		return n, err
	}
	return r.cur.Write(p)
}

func (r *retryConn) Read(p []byte) (int, error) {
	c, armed := r.conn()
	n, err := c.Read(p)
	if !armed {
		return n, err
	}
	var ne net.Error
	if n > 0 || err == nil || errors.As(err, &ne) && ne.Timeout() {
		r.mu.Lock()
		if r.cur == c {
			r.armed.Store(false)
			r.sent = nil
		}
		r.mu.Unlock()
		return n, err
	}
	r.mu.Lock()
	rerr := net.ErrClosed
	if r.cur != c || onlyTLSHandshake(r.sent) {
		rerr = r.retryLocked(c)
	} else {
		r.armed.Store(false)
		r.sent = nil
	}
	nc := r.cur
	r.mu.Unlock()
	if rerr != nil || nc == c {
		return n, err
	}
	return nc.Read(p)
}

// onlyTLSHandshake reports whether b is a whole number of TLS handshake
// records (type 0x16, version 3.x), e.g. a ClientHello. Empty b counts.
func onlyTLSHandshake(b []byte) bool {
	for len(b) > 0 {
		if len(b) < 5 || b[0] != 0x16 || b[1] != 0x03 {
			return false
		}
		n := int(b[3])<<8 | int(b[4])
		if n == 0 || len(b)-5 < n {
			return false
		}
		b = b[5+n:]
	}
	return true
}

func (r *retryConn) Close() error {
	r.st.Lock()
	r.closed = true
	c := r.cur
	r.st.Unlock()
	return c.Close()
}

// CloseWrite half-closes when the underlying conn supports it.
func (r *retryConn) CloseWrite() error {
	c, _ := r.conn()
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (r *retryConn) LocalAddr() net.Addr               { c, _ := r.conn(); return c.LocalAddr() }
func (r *retryConn) RemoteAddr() net.Addr              { c, _ := r.conn(); return c.RemoteAddr() }
func (r *retryConn) SetDeadline(t time.Time) error     { c, _ := r.conn(); return c.SetDeadline(t) }
func (r *retryConn) SetReadDeadline(t time.Time) error { c, _ := r.conn(); return c.SetReadDeadline(t) }
func (r *retryConn) SetWriteDeadline(t time.Time) error {
	c, _ := r.conn()
	return c.SetWriteDeadline(t)
}
