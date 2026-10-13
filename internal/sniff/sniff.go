// Package sniff extracts the destination domain from the first bytes of a
// TCP connection: the SNI of a TLS ClientHello or the Host of an HTTP/1.x
// request.
package sniff

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
)

var (
	// ErrNeedMore means the input is a valid prefix; read more and retry.
	ErrNeedMore = errors.New("sniff: need more data")
	ErrNotTLS   = errors.New("sniff: not a TLS ClientHello")
	ErrNotHTTP  = errors.New("sniff: not an HTTP request")
	// ErrNoDomain means the protocol was recognised but carries no domain
	// (no SNI extension, no Host header, or an IP literal).
	ErrNoDomain = errors.New("sniff: no domain")
)

// MaxTLSRecord is the largest TLS plaintext record (2^14) plus header.
const MaxTLSRecord = 5 + 1<<14

// MaxHTTPHeader bounds how much of an HTTP request is searched for Host.
const MaxHTTPHeader = 8 << 10

// Sniff tries TLS then HTTP. proto is "tls" or "http" when recognised.
func Sniff(b []byte) (domain, proto string, err error) {
	if len(b) == 0 {
		return "", "", ErrNeedMore
	}
	if b[0] == 0x16 {
		domain, err = SNI(b)
		return domain, "tls", err
	}
	domain, err = HTTPHost(b)
	if errors.Is(err, ErrNotHTTP) {
		return "", "", err
	}
	return domain, "http", err
}

// SNI returns the server_name from a TLS ClientHello contained in the first
// record of b. Only the first record is examined.
func SNI(b []byte) (string, error) { return sni(b, false) }

// SNIPrefix is SNI for a first record that is not complete and will not be
// waited for: the name is returned if it lies within b.
func SNIPrefix(b []byte) (string, error) { return sni(b, true) }

func sni(b []byte, prefix bool) (string, error) {
	if len(b) == 0 {
		return "", ErrNeedMore
	}
	if b[0] != 0x16 { // handshake
		return "", ErrNotTLS
	}
	if len(b) >= 2 && b[1] != 3 {
		return "", ErrNotTLS
	}
	if len(b) < 5 {
		return "", ErrNeedMore
	}
	n := int(b[3])<<8 | int(b[4])
	if n == 0 || n > 1<<14 {
		return "", ErrNotTLS
	}
	if len(b) < 5+n {
		if !prefix {
			return "", ErrNeedMore
		}
		n = len(b) - 5
	}
	p := reader(b[5 : 5+n])
	if t, ok := p.u8(); !ok || t != 1 { // client_hello
		return "", ErrNotTLS
	}
	hl, ok := p.u24()
	if !ok {
		return "", ErrNotTLS
	}
	if hl < len(p) {
		p = p[:hl]
	}
	// A ClientHello split across records is parsed as far as the first
	// record goes; the SNI is almost always within it.
	if !p.skip(2+32) || !p.skipVec8() || !p.skipVec16() || !p.skipVec8() {
		return "", ErrNotTLS
	}
	exts, ok := p.vec16()
	if !ok {
		if len(p) < 2 { // no extensions at all
			return "", ErrNoDomain
		}
		exts = p[2:] // truncated by the record boundary
	}
	for len(exts) >= 4 {
		typ, _ := exts.u16()
		ext, ok := exts.vec16()
		if !ok {
			break
		}
		if typ != 0 { // server_name
			continue
		}
		list, ok := ext.vec16()
		for ok && len(list) >= 3 {
			nt, _ := list.u8()
			name, ok2 := list.vec16()
			if !ok2 {
				break
			}
			if nt == 0 && len(name) > 0 { // host_name
				return domainOf(name)
			}
		}
		return "", ErrNoDomain
	}
	return "", ErrNoDomain
}

var methods = [...]string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

// HTTPHost returns the Host header of an HTTP/1.x request (port stripped,
// lowercased).
func HTTPHost(b []byte) (string, error) {
	known := false
	for _, m := range methods {
		if len(b) < len(m) {
			if strings.HasPrefix(m, string(b)) {
				return "", ErrNeedMore
			}
			continue
		}
		if string(b[:len(m)]) == m {
			known = true
			break
		}
	}
	if !known {
		return "", ErrNotHTTP
	}
	if len(b) > MaxHTTPHeader {
		b = b[:MaxHTTPHeader]
	}
	// Skip the request line, then scan complete header lines.
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		if len(b) == MaxHTTPHeader {
			return "", ErrNotHTTP
		}
		return "", ErrNeedMore
	}
	// A request to an HTTP proxy (CONNECT, or a full URL as the target)
	// names the site the proxy is asked for, not the proxy this connection
	// goes to: taken as the destination it sent the connection to the site
	// on the proxy's port, and every such connection failed (round 27).
	// Only a request to an origin server tells where it is going.
	if f := bytes.Fields(b[:i]); len(f) < 2 || f[0][0] == 'C' || f[1][0] != '/' && string(f[1]) != "*" {
		return "", ErrNoDomain
	}
	rest := b[i+1:]
	for {
		i = bytes.IndexByte(rest, '\n')
		if i < 0 {
			if len(b) == MaxHTTPHeader {
				return "", ErrNoDomain
			}
			return "", ErrNeedMore
		}
		line := bytes.TrimRight(rest[:i], "\r")
		rest = rest[i+1:]
		if len(line) == 0 { // end of headers
			return "", ErrNoDomain
		}
		k, v, ok := bytes.Cut(line, []byte{':'})
		if !ok || !bytes.EqualFold(bytes.TrimSpace(k), []byte("host")) {
			continue
		}
		h := bytes.TrimSpace(v)
		if len(h) > 0 && h[0] == '[' { // [v6]:port
			if j := bytes.IndexByte(h, ']'); j > 0 {
				h = h[1:j]
			}
		} else if j := bytes.LastIndexByte(h, ':'); j >= 0 {
			h = h[:j]
		}
		return domainOf(h)
	}
}

// domainOf validates and normalises a hostname; IP literals are rejected
// because the caller already knows the destination IP.
func domainOf(b []byte) (string, error) {
	b = bytes.TrimSuffix(b, []byte{'.'})
	if len(b) == 0 || len(b) > 253 {
		return "", ErrNoDomain
	}
	ipLike := true
	for _, c := range b {
		if c <= ' ' || c >= 0x7f || c == '/' {
			return "", ErrNoDomain
		}
		if c != '.' && c != ':' && (c < '0' || c > '9') && (c|0x20 < 'a' || c|0x20 > 'f') {
			ipLike = false
		}
	}
	s := strings.ToLower(string(b))
	if ipLike {
		if _, err := netip.ParseAddr(s); err == nil {
			return "", ErrNoDomain
		}
	}
	return s, nil
}

// reader is a bounds-checked big-endian cursor.
type reader []byte

func (r *reader) skip(n int) bool {
	if len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

func (r *reader) u8() (int, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	v := int((*r)[0])
	*r = (*r)[1:]
	return v, true
}

func (r *reader) u16() (int, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := int((*r)[0])<<8 | int((*r)[1])
	*r = (*r)[2:]
	return v, true
}

func (r *reader) u24() (int, bool) {
	if len(*r) < 3 {
		return 0, false
	}
	v := int((*r)[0])<<16 | int((*r)[1])<<8 | int((*r)[2])
	*r = (*r)[3:]
	return v, true
}

// vec16 reads a 2-byte length-prefixed vector. On failure r is unchanged.
func (r *reader) vec16() (reader, bool) {
	save := *r
	n, ok := r.u16()
	if !ok || len(*r) < n {
		*r = save
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *reader) skipVec8() bool {
	n, ok := r.u8()
	return ok && r.skip(n)
}

func (r *reader) skipVec16() bool {
	_, ok := r.vec16()
	return ok
}
