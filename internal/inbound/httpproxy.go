package inbound

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// maxHeader bounds the CONNECT request line plus headers.
const maxHeader = 8 << 10

var errHeaderTooLong = errors.New("http: request header too long")

// capReader returns errHeaderTooLong once n bytes have been read.
type capReader struct {
	r io.Reader
	n int
}

func (l *capReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errHeaderTooLong
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}

// readRequestHead reads a request line and skips the headers up to the
// blank line (RFC 9112 sections 3 and 5). Only the method and the target
// are used, so nothing else is kept: http.ReadRequest builds a header map
// of about 15 times the wire size, held while the head is incomplete. A
// request line must fit br's buffer.
func readRequestHead(br *bufio.Reader) (method, target string, err error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(string(line))
	if len(f) != 3 || !strings.HasPrefix(f[2], "HTTP/1.") {
		return "", "", errors.New("http: malformed request line")
	}
	method, target = f[0], f[1]
	for {
		if line, err = br.ReadSlice('\n'); err == bufio.ErrBufferFull {
			if err = skipLine(br); err != nil {
				return "", "", err
			}
			continue
		} else if err != nil {
			return "", "", err
		}
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			return method, target, nil
		}
	}
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

// ServeHTTP serves HTTP CONNECT proxying. Other methods get 405.
func ServeHTTP(ctx context.Context, ln net.Listener, h Handler) error {
	return serve(ctx, ln, func(c net.Conn) {
		conn, dst, err := httpConnect(c)
		if err != nil {
			c.Close()
			return
		}
		h.Handle(conn, srcOf(c), dst, dst.Domain == "")
	})
}

// httpConnect reads a CONNECT request and replies 200. The returned conn
// replays any bytes the client sent after the request headers.
func httpConnect(c net.Conn) (net.Conn, outbound.Addr, error) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	br := bufio.NewReaderSize(&capReader{r: c, n: maxHeader}, 4096)
	method, target, err := readRequestHead(br)
	if err != nil {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return nil, outbound.Addr{}, err
	}
	if method != http.MethodConnect {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return nil, outbound.Addr{}, errors.New("http: method not allowed")
	}
	host, port, err := net.SplitHostPort(target)
	p, perr := strconv.ParseUint(port, 10, 16)
	// 253: the longest DNS name. Every other name source is bounded (SOCKS
	// 255, sniffed names 253); rule matching costs grow with the length.
	if err != nil || perr != nil || host == "" || len(host) > 253 || p == 0 {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return nil, outbound.Addr{}, errors.New("http: bad CONNECT target")
	}
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return nil, outbound.Addr{}, err
	}
	var conn net.Conn = c
	if n := br.Buffered(); n > 0 {
		buf, _ := br.Peek(n)
		conn = &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(append([]byte(nil), buf...)), c)}
	}
	return conn, addr(host, uint16(p)), nil
}
