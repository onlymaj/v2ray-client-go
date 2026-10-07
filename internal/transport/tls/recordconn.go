package tls

import (
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
}

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
