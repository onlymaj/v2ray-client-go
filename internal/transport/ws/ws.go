//go:build ws

// Package ws is a minimal RFC 6455 WebSocket client layer, compatible with
// Xray's "ws" transport (transport/internet/websocket). Only what a proxy
// tunnel needs is implemented: the HTTP/1.1 Upgrade handshake, masked
// binary frames on write, binary/continuation frames on read, ping->pong and
// close. Text frames are read as data too; extensions are not negotiated.
package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/onlymaj/v2ray-client-go/internal/transport"
)

func init() { transport.Register("ws", New) }

// Settings is the JSON settings blob of the "ws" layer.
//
//	{"path":"/","host":"","headers":{}}
//
// A "?ed=N" query in path enables Xray early data: the first Write of at
// most N bytes is sent base64-RawURL in Sec-WebSocket-Protocol and the
// handshake is delayed until that Write (Xray infra/conf WebSocketConfig.Build
// and websocket/dialer.go delayDialConn).
type Settings struct {
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
}

type layer struct {
	path    string // normalized request-target, "ed" removed
	host    string
	headers http.Header
	ed      int
}

// New is the transport.Factory for "ws".
func New(settings []byte) (transport.Layer, error) {
	var s Settings
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &s); err != nil {
			return nil, fmt.Errorf("ws: settings: %w", err)
		}
	}
	l := &layer{path: s.Path, host: s.Host, headers: http.Header{}}
	// Mirrors infra/conf WebSocketConfig.Build: pull "ed" out of the query.
	if u, err := url.Parse(l.path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			l.ed, _ = strconv.Atoi(q.Get("ed"))
			q.Del("ed")
			u.RawQuery = q.Encode()
			l.path = u.String()
		}
	}
	// websocket/config.go GetNormalizedPath.
	if l.path == "" || l.path[0] != '/' {
		l.path = "/" + l.path
	}
	if strings.ContainsFunc(l.path, func(r rune) bool { return r <= ' ' || r == 0x7F }) {
		return nil, fmt.Errorf("ws: invalid path %q", s.Path)
	}
	for k, v := range s.Headers {
		if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) {
			return nil, fmt.Errorf("ws: invalid header %q: %q", k, v)
		}
		// Deprecated "host" in headers (Xray: only used when host is empty).
		if strings.EqualFold(k, "host") {
			if l.host == "" {
				l.host = v
			}
			continue
		}
		l.headers.Set(k, v)
	}
	if l.host != "" && !httpguts.ValidHostHeader(l.host) {
		return nil, fmt.Errorf("ws: invalid host %q", l.host)
	}
	return l, nil
}

// Wrap performs the WebSocket handshake over conn. With early data enabled
// the handshake is deferred until the first Write.
func (l *layer) Wrap(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if l.ed > 0 {
		return &delayConn{Conn: conn, l: l, dialed: make(chan struct{}), rdl: deadline{cancel: make(chan struct{})}}, nil
	}
	return l.handshake(ctx, conn, nil)
}

// handshake sends the opening handshake (RFC 6455 section 4.1) and checks
// the server's 101 response.
func (l *layer) handshake(ctx context.Context, conn net.Conn, ed []byte) (*Conn, error) {
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
		defer conn.SetDeadline(time.Time{})
	}
	host := l.host
	if host == "" {
		// The lead should pass host (Xray: host > TLS serverName > address).
		host, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])

	var b strings.Builder
	b.WriteString("GET " + l.path + " HTTP/1.1\r\nHost: " + host + "\r\n")
	b.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n")
	b.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	if ed != nil {
		// RawURLEncoding is supported by both V2Ray/V2Fly and Xray.
		b.WriteString("Sec-WebSocket-Protocol: " + base64.RawURLEncoding.EncodeToString(ed) + "\r\n")
	}
	if l.headers.Get("User-Agent") == "" {
		b.WriteString("User-Agent: Go-http-client/1.1\r\n")
	}
	for k, vs := range l.headers {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, fmt.Errorf("ws: handshake: %w", err)
	}

	// Bound the response header so a server cannot grow it without limit;
	// the limit is lifted once the handshake is done.
	hr := &handshakeReader{r: conn, n: maxHandshake}
	br := bufio.NewReaderSize(hr, 4096)
	status, upgrade, accept, err := readHandshake(br)
	if err != nil {
		return nil, fmt.Errorf("ws: handshake: %w", err)
	}
	if status != http.StatusSwitchingProtocols || !strings.EqualFold(upgrade, "websocket") || accept != acceptKey(key) {
		return nil, fmt.Errorf("ws: handshake: bad response (HTTP %d)", status) // not the status text: it is the server's
	}
	hr.n = -1
	return &Conn{Conn: conn, br: br}, nil
}

// maxHandshake bounds the bytes read for the handshake response. A real one
// is a few hundred bytes, some more behind a CDN.
const maxHandshake = 16 << 10

// readHandshake reads the response head (RFC 9112 sections 4 and 5) and
// returns the status code and the two header values the handshake needs.
// Nothing else is kept: http.ReadResponse builds a header map of about 15
// times the wire size, and a server that never ended the head made every
// handshake hold a megabyte until the dial timeout. A line must fit br's
// buffer, or it is skipped.
func readHandshake(br *bufio.Reader) (status int, upgrade, accept string, err error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		return 0, "", "", err
	}
	// "HTTP/1.1 101 Switching Protocols"
	f := strings.Fields(string(line))
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") || len(f[1]) != 3 {
		return 0, "", "", errors.New("malformed response")
	}
	if status, err = strconv.Atoi(f[1]); err != nil {
		return 0, "", "", errors.New("malformed response")
	}
	for {
		if line, err = br.ReadSlice('\n'); err == bufio.ErrBufferFull {
			// A long header is not one of ours; the total is capped.
			if err = skipLine(br); err != nil {
				return 0, "", "", err
			}
			continue
		} else if err != nil {
			return 0, "", "", err
		}
		l := strings.TrimRight(string(line), "\r\n")
		if l == "" {
			return status, upgrade, accept, nil
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return 0, "", "", errors.New("malformed response header")
		}
		switch v = strings.TrimSpace(v); {
		case strings.EqualFold(k, "Upgrade"):
			upgrade = v
		case strings.EqualFold(k, "Sec-WebSocket-Accept"):
			accept = v
		}
	}
}

var errHandshakeTooLarge = errors.New("ws: handshake response too large")

// handshakeReader reads from r, failing after n bytes; n < 0 means no limit.
type handshakeReader struct {
	r io.Reader
	n int64
}

func (h *handshakeReader) Read(p []byte) (int, error) {
	if h.n < 0 {
		return h.r.Read(p)
	}
	if h.n == 0 {
		return 0, errHandshakeTooLarge
	}
	if int64(len(p)) > h.n {
		p = p[:h.n]
	}
	n, err := h.r.Read(p)
	h.n -= int64(n)
	return n, err
}

// skipLine reads the rest of a header line that did not fit br's buffer.
func skipLine(br *bufio.Reader) error {
	for {
		_, err := br.ReadSlice('\n')
		if err != bufio.ErrBufferFull {
			return err
		}
	}
}

// acceptKey computes Sec-WebSocket-Accept (RFC 6455 section 4.2.2 step 5.4).
func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

// RFC 6455 section 5.2 opcodes.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// Conn is a client WebSocket connection carrying a byte stream in binary
// messages. Message boundaries are not preserved on read.
type Conn struct {
	net.Conn
	br *bufio.Reader

	wmu    sync.Mutex // serializes frames (data, pong, close)
	closed bool       // close frame sent; guarded by wmu

	remain int64   // payload bytes left in the current data frame
	mask   [4]byte // server frames must not be masked, tolerated anyway
	masked bool
	pos    int // mask offset within the current frame
}

// Read returns payload bytes of data frames, answering pings and stopping
// at a close frame (io.EOF). Frame headers and control frames are only
// consumed once complete (bufio Peek), so a read deadline expiring
// mid-frame leaves the stream intact and Read can be retried.
func (c *Conn) Read(p []byte) (int, error) {
	for c.remain == 0 {
		hlen, op, n, err := c.peekHeader()
		if err != nil {
			return 0, err
		}
		switch op {
		case opContinuation, opText, opBinary:
			c.br.Discard(hlen)
			c.remain = n
		case opPing, opPong, opClose:
			// Control frames: payload <= 125 bytes (section 5.5).
			if n > 125 {
				return 0, errors.New("ws: control frame too long")
			}
			b, err := c.br.Peek(hlen + int(n))
			if err != nil {
				return 0, err
			}
			payload := append([]byte(nil), b[hlen:]...)
			c.br.Discard(len(b))
			c.unmask(payload)
			if op == opPing {
				c.writeFrame(opPong, payload) // section 5.5.3
			} else if op == opClose {
				// Echo the status code back (section 5.5.1).
				if len(payload) > 2 {
					payload = payload[:2]
				}
				c.writeFrame(opClose, payload)
				return 0, io.EOF
			}
		default:
			return 0, fmt.Errorf("ws: unknown opcode %d", op)
		}
	}
	if int64(len(p)) > c.remain {
		p = p[:c.remain]
	}
	n, err := c.br.Read(p)
	c.unmask(p[:n])
	c.remain -= int64(n)
	return n, err
}

// peekHeader parses a frame header (RFC 6455 section 5.2) without
// consuming it and returns its length.
func (c *Conn) peekHeader() (hlen int, op byte, n int64, err error) {
	h, err := c.br.Peek(2)
	if err != nil {
		return
	}
	op = h[0] & 0x0F
	c.masked = h[1]&0x80 != 0
	n = int64(h[1] & 0x7F)
	hlen = 2
	switch n {
	case 126:
		hlen += 2
	case 127:
		hlen += 8
	}
	if c.masked {
		hlen += 4
	}
	if h, err = c.br.Peek(hlen); err != nil {
		return
	}
	switch n {
	case 126:
		n = int64(binary.BigEndian.Uint16(h[2:]))
	case 127:
		n = int64(binary.BigEndian.Uint64(h[2:]))
		if n < 0 {
			return 0, 0, 0, errors.New("ws: frame too long")
		}
	}
	if c.masked {
		copy(c.mask[:], h[hlen-4:])
	}
	c.pos = 0
	return hlen, op, n, nil
}

func (c *Conn) unmask(b []byte) {
	if !c.masked {
		return
	}
	for i := range b {
		b[i] ^= c.mask[(c.pos+i)&3]
	}
	c.pos += len(b)
}

// Write sends p as one masked binary frame.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.writeFrame(opBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeFrame sends one final frame. Client frames are always masked
// (RFC 6455 section 5.3).
func (c *Conn) writeFrame(op byte, p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeFrameLocked(op, p)
}

// writeFrameLocked is writeFrame with wmu already held.
func (c *Conn) writeFrameLocked(op byte, p []byte) error {
	if c.closed {
		return net.ErrClosed
	}
	if op == opClose {
		c.closed = true
	}
	buf := make([]byte, 14+len(p))
	buf[0] = 0x80 | op // FIN
	n := 2
	switch l := len(p); {
	case l <= 125:
		buf[1] = byte(l)
	case l <= 0xFFFF:
		buf[1] = 126
		binary.BigEndian.PutUint16(buf[2:], uint16(l))
		n += 2
	default:
		buf[1] = 127
		binary.BigEndian.PutUint64(buf[2:], uint64(l))
		n += 8
	}
	buf[1] |= 0x80 // MASK
	key := buf[n : n+4]
	rand.Read(key)
	n += 4
	for i, b := range p {
		buf[n+i] = b ^ key[i&3]
	}
	_, err := c.Conn.Write(buf[:n+len(p)])
	return err
}

// Close sends a 1000 (normal closure) close frame when it can do so without
// waiting, then closes the connection. If a Write is stuck holding the frame
// lock (a stalled peer), it closes the underlying conn directly, which also
// unblocks that Write: Close must never hang (relays are closed from config
// updates).
func (c *Conn) Close() error {
	if c.wmu.TryLock() {
		if !c.closed {
			c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
			c.writeFrameLocked(opClose, []byte{0x03, 0xE8})
		}
		c.wmu.Unlock()
	}
	return c.Conn.Close()
}

// earlyDataError is a failed handshake whose request carried early data.
// The server may have taken the request and passed the data on before the
// failure, so a caller must not send that data again on another connection
// unless twice does no harm (round 24).
type earlyDataError struct{ error }

func (e earlyDataError) Unwrap() error      { return e.error }
func (earlyDataError) MayBeDelivered() bool { return true }

// earlyDataTimeout bounds the handshake deferred to the first Write.
const earlyDataTimeout = 15 * time.Second

// delayConn defers the handshake to the first Write so it can carry early
// data (mirrors Xray websocket/dialer.go delayDialConn). The embedded raw
// conn provides addresses and deadlines.
type delayConn struct {
	net.Conn
	l      *layer
	once   sync.Once
	dialed chan struct{} // closed once ws/err are set
	ws     *Conn
	err    error
	rdl    deadline // read deadline while waiting for the handshake
}

func (d *delayConn) SetDeadline(t time.Time) error {
	d.rdl.set(t)
	return d.Conn.SetDeadline(t)
}

func (d *delayConn) SetReadDeadline(t time.Time) error {
	d.rdl.set(t)
	return d.Conn.SetReadDeadline(t)
}

func (d *delayConn) Write(p []byte) (int, error) {
	wrote := false
	d.once.Do(func() {
		ed := p
		if len(ed) > d.l.ed {
			ed = nil
		}
		// The timeout closes the conn instead of setting a deadline on it:
		// handshake would clear the deadline afterwards, and with it one
		// the caller set meanwhile to interrupt its own Read.
		ctx, cancel := context.WithTimeout(context.Background(), earlyDataTimeout)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { d.Conn.Close() })
		defer stop()
		d.ws, d.err = d.l.handshake(context.Background(), d.Conn, ed)
		if d.err != nil && ed != nil {
			d.err = earlyDataError{d.err}
		}
		wrote = d.err == nil && ed != nil
		close(d.dialed)
	})
	<-d.dialed
	if d.err != nil {
		return 0, d.err
	}
	if wrote {
		return len(p), nil
	}
	return d.ws.Write(p)
}

func (d *delayConn) Read(p []byte) (int, error) {
	select {
	case <-d.dialed:
	case <-d.rdl.wait():
		return 0, os.ErrDeadlineExceeded
	}
	if d.err != nil {
		return 0, d.err
	}
	return d.ws.Read(p)
}

func (d *delayConn) Close() error {
	select {
	case <-d.dialed:
		if d.ws != nil {
			return d.ws.Close()
		}
	default:
	}
	// Closing the raw conn aborts an in-flight handshake; once.Do then
	// waits for it and unblocks pending Reads either way.
	err := d.Conn.Close()
	d.once.Do(func() { d.err = net.ErrClosed; close(d.dialed) })
	return err
}

// deadline is a channel closed when the deadline passes; a copy of
// pipeDeadline in Go's net/pipe.go.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // wait for the timer callback to close cancel
	}
	d.timer = nil
	closed := false
	select {
	case <-d.cancel:
		closed = true
	default:
	}
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		c := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(c) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}
