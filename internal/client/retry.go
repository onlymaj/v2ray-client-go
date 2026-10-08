package client

import (
	"errors"
	"net"
	"sync"
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
// rather than in Dial. A server that legitimately closes before sending
// anything is retried once too, which only costs one extra dial.
type retryConn struct {
	redial func() (net.Conn, error)

	mu     sync.Mutex // held during armed Writes and the redial
	cur    net.Conn
	armed  bool
	closed bool
	sent   []byte
}

func newRetryConn(c net.Conn, redial func() (net.Conn, error)) *retryConn {
	return &retryConn{cur: c, redial: redial, armed: true}
}

func (r *retryConn) conn() (net.Conn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur, r.armed
}

// retry replaces old with a fresh conn unless that already happened. The
// caller holds r.mu.
func (r *retryConn) retryLocked(old net.Conn) error {
	if r.cur != old {
		return nil
	}
	if !r.armed || r.closed {
		return net.ErrClosed
	}
	r.armed = false
	old.Close()
	nc, err := r.redial()
	if err != nil {
		return err
	}
	if len(r.sent) > 0 {
		if _, err := nc.Write(r.sent); err != nil {
			nc.Close()
			return err
		}
	}
	r.sent = nil
	r.cur = nc
	return nil
}

func (r *retryConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	if !r.armed {
		c := r.cur
		r.mu.Unlock()
		return c.Write(p)
	}
	defer r.mu.Unlock()
	old := r.cur
	n, err := old.Write(p)
	if err == nil {
		if len(r.sent)+len(p) > retryLimit {
			r.armed, r.sent = false, nil
		} else {
			r.sent = append(r.sent, p...)
		}
		return n, nil
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
			r.armed, r.sent = false, nil
		}
		r.mu.Unlock()
		return n, err
	}
	r.mu.Lock()
	rerr := r.retryLocked(c)
	nc := r.cur
	r.mu.Unlock()
	if rerr != nil || nc == c {
		return n, err
	}
	return nc.Read(p)
}

func (r *retryConn) Close() error {
	r.mu.Lock()
	r.closed = true
	c := r.cur
	r.mu.Unlock()
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
