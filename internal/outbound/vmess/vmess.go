//go:build vmess

// Package vmess is a VMess (AEAD header only) client outbound. Protocol code
// mirrors Xray's proxy/vmess/{aead,encoding,outbound}.
package vmess

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"runtime"
	"strings"
	"sync"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

func init() { outbound.Register("vmess", newDialer) }

// Settings is the "vmess" settings JSON.
type Settings struct {
	ID       string `json:"id"`
	Security string `json:"security"` // auto | aes-128-gcm | chacha20-poly1305 | none | zero
	AlterID  int    `json:"alterId"`  // must be 0: legacy MD5 auth is not supported
	// AllowNonceWrap lets the 16-bit chunk counter wrap (nonce reuse under
	// the body key after 65536 chunks) as Xray does, instead of failing the
	// stream. Set it only when VMess runs inside TLS or REALITY: the outer
	// AEAD then provides confidentiality and integrity on its own, so a
	// repeated inner nonce exposes nothing to the network. Without an outer
	// layer, a wrap would leak the XOR of plaintexts and allow forgeries.
	AllowNonceWrap bool `json:"allowNonceWrap"`
}

type dialer struct {
	cmdKey        [16]byte
	security      byte // secAES128GCM | secChaCha20 | secNone | secZero
	nonceWrap     bool // Settings.AllowNonceWrap
	dialTransport func(ctx context.Context) (net.Conn, error)
}

func newDialer(settings []byte, dialTransport func(ctx context.Context) (net.Conn, error)) (outbound.Dialer, error) {
	var s Settings
	if err := json.Unmarshal(settings, &s); err != nil {
		return nil, fmt.Errorf("vmess: settings: %w", err)
	}
	if s.AlterID != 0 {
		return nil, errors.New("vmess: alterId must be 0 (only AEAD is supported)")
	}
	id, err := parseUUID(s.ID)
	if err != nil {
		return nil, err
	}
	d := &dialer{dialTransport: dialTransport, nonceWrap: s.AllowNonceWrap}
	// common/protocol/id.go NewID: cmdKey = md5(uuid | fixed salt).
	d.cmdKey = md5.Sum(append(id[:], "c48619fe-8f02-49e0-b9e9-edf763e17e21"...))
	switch strings.ToLower(s.Security) {
	case "", "auto":
		// common/protocol/headers.go GetSecurityType: AES-GCM when the CPU
		// has AES instructions (arm64 and amd64 do), else ChaCha20.
		if runtime.GOARCH == "arm64" || runtime.GOARCH == "amd64" {
			d.security = secAES128GCM
		} else {
			d.security = secChaCha20
		}
	case "aes-128-gcm":
		d.security = secAES128GCM
	case "chacha20-poly1305":
		d.security = secChaCha20
	case "none":
		d.security = secNone
	case "zero":
		d.security = secZero
	default:
		return nil, fmt.Errorf("vmess: unknown security %q", s.Security)
	}
	return d, nil
}

// parseUUID mirrors common/uuid/uuid.go ParseString, including mapping a
// short (1-30 byte) string to a UUIDv5 under the zero namespace.
func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	if l := len(s); l < 32 || l > 36 {
		if l == 0 || l > 30 {
			return u, fmt.Errorf("vmess: invalid id %q", s)
		}
		h := sha1.New()
		h.Write(u[:])
		h.Write([]byte(s))
		copy(u[:], h.Sum(nil))
		u[6] = u[6]&0x0f | 5<<4
		u[8] = u[8]&0x3f | 0x80
		return u, nil
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return u, fmt.Errorf("vmess: invalid id %q", s)
	}
	copy(u[:], b)
	return u, nil
}

// options mirrors proxy/vmess/outbound/outbound.go Process: ChunkStream
// always; ChunkMasking for aes/chacha/none; GlobalPadding for aes/chacha
// (shouldEnablePadding); "zero" clears everything and is sent as none.
// AuthenticatedLength is an opt-in experiment in Xray and is not sent.
func options(security byte) (wireSec, opt byte) {
	switch security {
	case secAES128GCM, secChaCha20:
		return security, optChunkStream | optChunkMasking | optGlobalPadding
	case secNone:
		return secNone, optChunkStream | optChunkMasking
	default: // secZero
		return secNone, 0
	}
}

func (d *dialer) Dial(ctx context.Context, network string, dest outbound.Addr) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("vmess: unsupported network %q", network)
	}
	c, err := newClientConn(d.cmdKey, d.security, dest)
	if err != nil {
		return nil, err
	}
	if c.enc != nil {
		c.enc.wrap, c.dec.wrap = d.nonceWrap, d.nonceWrap
	}
	conn, err := d.dialTransport(ctx)
	if err != nil {
		return nil, err
	}
	c.Conn = conn
	c.br = bufio.NewReaderSize(conn, bufSize)
	return c, nil
}

// clientConn is the proxied stream. The request header is sent together with
// the first Write (Xray's outbound also buffers it with the first payload),
// or before the first Read if the client reads first. The response header is
// consumed on the first Read.
type clientConn struct {
	net.Conn
	br *bufio.Reader

	wmu     sync.Mutex
	header  []byte // pending request header; nil once sent
	enc     *chunkCodec
	wclosed bool

	rmu      sync.Mutex
	respKey  [16]byte
	respIV   [16]byte
	respV    byte
	gotResp  bool
	dec      *chunkCodec
	rbuf     []byte // reusable chunk buffer
	leftover []byte // decrypted bytes not yet returned
	rerr     error
}

func newClientConn(cmdKey [16]byte, security byte, dest outbound.Addr) (*clientConn, error) {
	// encoding/client.go NewClientSession: random body key, IV and V; the
	// response key/IV are SHA-256 of the request ones, truncated.
	var r [33]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	reqIV, reqKey, v := r[:16], r[16:32], r[32]
	c := &clientConn{respV: v}
	rk, ri := sha256.Sum256(reqKey), sha256.Sum256(reqIV)
	copy(c.respKey[:], rk[:16])
	copy(c.respIV[:], ri[:16])

	wireSec, opt := options(security)

	// encoding/client.go EncodeRequestHeader.
	var pad [1]byte
	rand.Read(pad[:])
	padLen := int(pad[0] % 16)
	h := make([]byte, 0, 64+256)
	h = append(h, 1) // version
	h = append(h, reqIV...)
	h = append(h, reqKey...)
	h = append(h, v, opt, byte(padLen<<4)|wireSec, 0, 0x01 /* TCP */)
	h, err := appendAddr(h, dest)
	if err != nil {
		return nil, err
	}
	h = append(h, make([]byte, padLen)...)
	rand.Read(h[len(h)-padLen:])
	fh := fnv.New32a()
	fh.Write(h)
	h = fh.Sum(h)
	c.header = sealHeader(cmdKey, h)

	if opt&optChunkStream != 0 {
		c.enc = newChunkCodec(wireSec, reqKey, reqIV, opt)
		c.dec = newChunkCodec(wireSec, c.respKey[:], c.respIV[:], opt)
	}
	return c, nil
}

// appendAddr writes VMess's port-then-address form (encoding/encoding.go
// addrParser with PortThenAddress): port(2) | type | addr, where type is
// 1 IPv4, 2 domain (length-prefixed), 3 IPv6.
func appendAddr(b []byte, a outbound.Addr) ([]byte, error) {
	b = append(b, byte(a.Port>>8), byte(a.Port))
	switch {
	case a.Domain != "":
		if len(a.Domain) > 255 {
			return nil, errors.New("vmess: domain too long")
		}
		b = append(b, 2, byte(len(a.Domain)))
		return append(b, a.Domain...), nil
	case a.IP.Unmap().Is4():
		ip := a.IP.Unmap().As4()
		return append(append(b, 1), ip[:]...), nil
	case a.IP.Is6():
		ip := a.IP.As16()
		return append(append(b, 3), ip[:]...), nil
	}
	return nil, errors.New("vmess: empty destination")
}

func (c *clientConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wclosed {
		return 0, net.ErrClosed
	}
	if c.enc == nil && c.header == nil { // zero: raw body
		return c.Conn.Write(p)
	}
	// The buffer is borrowed for this call: kept in the conn it stayed at
	// 21 KiB after one large write, for the life of every connection
	// (round 21).
	bp := wbufPool.Get().(*[]byte)
	defer func() { wbufPool.Put(bp) }()
	if c.enc == nil {
		*bp = append(append((*bp)[:0], c.header...), p...)
		if _, err := c.Conn.Write(*bp); err != nil {
			return 0, err
		}
		c.header = nil
		return len(p), nil
	}
	n := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), c.enc.maxPayload())]
		// Batch a few chunks per syscall.
		w := append((*bp)[:0], c.header...)
		for len(chunk) > 0 && len(w) < 4*bufSize {
			var err error
			if w, err = c.enc.seal(w, chunk); err != nil {
				*bp = w
				c.Conn.Close()
				return n, err
			}
			p = p[len(chunk):]
			n += len(chunk)
			chunk = p[:min(len(p), c.enc.maxPayload())]
		}
		*bp = w
		if _, err := c.Conn.Write(w); err != nil {
			return n, err
		}
		c.header = nil
	}
	return n, nil
}

// wbufPool and rbufPool hold the write and chunk buffers between uses.
var (
	wbufPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}
	rbufPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}
)

// releaseRbuf gives the chunk buffer back once nothing of it is left to
// deliver, so that a connection waiting for data holds none.
func (c *clientConn) releaseRbuf() {
	if c.rbuf != nil {
		b := c.rbuf[:0]
		rbufPool.Put(&b)
		c.rbuf = nil
	}
}

// flushHeaderLocked sends the request header alone (wmu held).
func (c *clientConn) flushHeaderLocked() error {
	if c.header == nil {
		return nil
	}
	_, err := c.Conn.Write(c.header)
	c.header = nil
	return err
}

// CloseWrite sends the end-of-stream chunk (proxy/vmess/outbound Process
// writes an empty MultiBuffer when the input ends) and half-closes the
// transport when it supports that.
func (c *clientConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wclosed {
		return nil
	}
	c.wclosed = true
	if c.enc != nil {
		last, err := c.enc.seal(append([]byte(nil), c.header...), nil)
		if err != nil {
			c.Conn.Close()
			return err
		}
		c.header = nil
		if _, err := c.Conn.Write(last); err != nil {
			return err
		}
	} else if err := c.flushHeaderLocked(); err != nil {
		return err
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *clientConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		if c.leftover = c.leftover[n:]; len(c.leftover) == 0 {
			c.leftover = nil // don't pin an oversized chunk while idle
			c.releaseRbuf()
		}
		return n, nil
	}
	if c.rerr != nil {
		return 0, c.rerr
	}
	if !c.gotResp {
		// The server answers only after it has the request header.
		c.wmu.Lock()
		err := c.flushHeaderLocked()
		c.wmu.Unlock()
		if err != nil {
			return 0, err
		}
		hdr, err := readResponseHeader(c.br, c.respKey[:], c.respIV[:])
		if err == nil && hdr[0] != c.respV {
			err = errors.New("vmess: unexpected response header")
		}
		if err != nil {
			c.rerr = err
			return 0, err
		}
		c.gotResp = true // hdr[1:] (option, dynamic port command) is ignored
	}
	if c.dec == nil { // zero: raw body
		return c.br.Read(p)
	}
	for {
		if c.rbuf == nil {
			// Wait for the chunk's size without the buffer: a relay is
			// always in Read, so every idle conn held one, up to 20 KiB
			// (round 22).
			if _, err := c.br.Peek(2); err != nil {
				c.rerr = err
				return 0, err
			}
			c.rbuf = *rbufPool.Get().(*[]byte)
		}
		pt, err := c.dec.open(c.br, c.rbuf)
		if err != nil {
			if err == errNonceExhausted {
				c.Conn.Close()
			}
			c.rerr = err
			c.releaseRbuf()
			return 0, err
		}
		// Keep a grown buffer only up to the usual chunk size, so a server
		// sending one 64 KB chunk doesn't make every conn hold 64 KB.
		if cap(pt) > cap(c.rbuf) && cap(pt) <= 20<<10 {
			c.rbuf = pt[:0]
		}
		if len(pt) == 0 {
			continue
		}
		n := copy(p, pt)
		if c.leftover = pt[n:]; len(c.leftover) == 0 {
			c.leftover = nil
			c.releaseRbuf()
		}
		return n, nil
	}
}
