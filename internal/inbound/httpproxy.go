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
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

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
	br := bufio.NewReaderSize(c, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return nil, outbound.Addr{}, err
	}
	if req.Method != http.MethodConnect {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return nil, outbound.Addr{}, errors.New("http: method not allowed")
	}
	host, port, err := net.SplitHostPort(req.Host)
	p, perr := strconv.ParseUint(port, 10, 16)
	if err != nil || perr != nil || host == "" || p == 0 {
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
