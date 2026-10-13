package tls

import (
	"errors"
	"net"
	"sync/atomic"
)

// RecordConn sits between uTLS and the raw TCP connection. Its Read never
// returns bytes past the end of the current TLS record, so uTLS's internal
// rawInput buffer can never hold bytes that belong to a later record.
//
// Why: XTLS Vision (internal/outbound/vless/vision.go) lets the server stop
// using the outer TLS mid-stream and write raw bytes onto TCP right after a
// "direct" command. Xray recovers bytes uTLS already over-read by poking at
// the unexported Conn.input/rawInput fields with unsafe (see UnwrapRawConn
// and the reflect block in proxy/vless/outbound/outbound.go). Keeping uTLS
// record-aligned lets us switch to raw reads without unsafe: everything past
// the last TLS record is still here, in our own buffer.
type RecordConn struct {
	net.Conn

	buf  []byte
	r, w int

	hdr     [5]byte
	hdrLeft int // header bytes still to hand out (0 while inside a body)
	body    int // body bytes still to hand out
	raw     atomic.Bool

	// limit bounds the bytes handed to uTLS since the last Progress (or
	// SetLimit); 0 is no limit. See MaxHandshakeIn and MaxQuietIn.
	limit, passed atomic.Int64
}

// What uTLS may take in without giving anything back (round 20). uTLS has
// limits of its own, but they are sized for a desktop: a 256 KiB
// certificate message, whose certificates it then keeps for the life of
// the connection (350 KiB measured), and after the handshake a 64 KiB
// handshake message collected in a buffer of twice that, with nothing
// delivered and no error. A proxy server could park that in every
// connection.
const (
	// MaxHandshakeIn is for the whole handshake. A server's flight is 3 to
	// 12 KiB; the largest certificate chains in use are below 30 KiB.
	MaxHandshakeIn = 64 << 10
	// MaxQuietIn is for the bytes between two deliveries of plaintext: one
	// full record (16 KiB + 261) and the session tickets or key updates
	// that may come before it.
	MaxQuietIn = 24 << 10
)

var errQuiet = errors.New("tls: too many bytes from the server without data")

// SetLimit starts a new count with limit n.
func (c *RecordConn) SetLimit(n int) {
	c.passed.Store(0)
	c.limit.Store(int64(n))
}

// Progress is called when uTLS has delivered plaintext.
func (c *RecordConn) Progress() { c.passed.Store(0) }

func NewRecordConn(c net.Conn) *RecordConn {
	return &RecordConn{Conn: c, buf: make([]byte, 8192), hdrLeft: 5}
}

// SetRaw stops record framing; later reads return whatever is buffered or
// arrives. Called by Vision when it takes over reading from uTLS.
func (c *RecordConn) SetRaw() { c.raw.Store(true) }

func (c *RecordConn) Read(p []byte) (int, error) {
	if c.r == c.w {
		if c.raw.Load() && len(p) >= len(c.buf) {
			return c.Conn.Read(p) // nothing buffered: read straight through
		}
		n, err := c.Conn.Read(c.buf)
		if n <= 0 {
			return 0, err
		}
		c.r, c.w = 0, n
	}
	n := c.w - c.r
	if n > len(p) {
		n = len(p)
	}
	if !c.raw.Load() {
		limit := c.body
		if c.hdrLeft > 0 {
			limit = c.hdrLeft
		}
		if n > limit {
			n = limit
		}
		if l := c.limit.Load(); l > 0 && c.passed.Add(int64(n)) > l {
			return 0, errQuiet
		}
		c.track(c.buf[c.r : c.r+n])
	}
	copy(p, c.buf[c.r:c.r+n])
	c.r += n
	return n, nil
}

// track advances the record parser over b, which never crosses a boundary.
func (c *RecordConn) track(b []byte) {
	if c.hdrLeft > 0 {
		copy(c.hdr[5-c.hdrLeft:], b)
		c.hdrLeft -= len(b)
		if c.hdrLeft == 0 {
			c.body = int(c.hdr[3])<<8 | int(c.hdr[4])
			if c.body == 0 {
				c.hdrLeft = 5
			}
		}
		return
	}
	c.body -= len(b)
	if c.body == 0 {
		c.hdrLeft = 5
	}
}
