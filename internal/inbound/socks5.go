package inbound

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// SOCKS5 (RFC 1928) constants.
const (
	socksVer       = 5
	methodNoAuth   = 0
	methodNone     = 0xff
	cmdConnect     = 1
	atypIPv4       = 1
	atypDomain     = 3
	atypIPv6       = 4
	repSuccess     = 0
	repCmdNotSupp  = 7
	repAtypNotSupp = 8
)

// ServeSOCKS serves SOCKS5 without authentication, CONNECT only.
func ServeSOCKS(ctx context.Context, ln net.Listener, h Handler) error {
	return serve(ctx, ln, func(c net.Conn) {
		dst, err := socksHandshake(c)
		if err != nil {
			c.Close()
			return
		}
		h.Handle(c, srcOf(c), dst, dst.Domain == "")
	})
}

// socksHandshake negotiates "no auth", reads a CONNECT request and replies
// success (the outcome of the dial is reported by closing the conn). It
// reads exactly the request bytes so pipelined data stays in the conn.
func socksHandshake(c net.Conn) (outbound.Addr, error) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	var b [262]byte
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return outbound.Addr{}, err
	}
	if b[0] != socksVer {
		return outbound.Addr{}, errors.New("socks: bad version")
	}
	methods := b[2 : 2+int(b[1])]
	if _, err := io.ReadFull(c, methods); err != nil {
		return outbound.Addr{}, err
	}
	ok := false
	for _, m := range methods {
		ok = ok || m == methodNoAuth
	}
	if !ok {
		c.Write([]byte{socksVer, methodNone})
		return outbound.Addr{}, errors.New("socks: no acceptable auth method")
	}
	if _, err := c.Write([]byte{socksVer, methodNoAuth}); err != nil {
		return outbound.Addr{}, err
	}

	// VER CMD RSV ATYP
	if _, err := io.ReadFull(c, b[:4]); err != nil {
		return outbound.Addr{}, err
	}
	if b[0] != socksVer {
		return outbound.Addr{}, errors.New("socks: bad version")
	}
	cmd := b[1]
	var dst outbound.Addr
	switch b[3] {
	case atypIPv4:
		if _, err := io.ReadFull(c, b[:4+2]); err != nil {
			return dst, err
		}
		dst.IP = netip.AddrFrom4([4]byte(b[:4]))
		dst.Port = binary.BigEndian.Uint16(b[4:])
	case atypIPv6:
		if _, err := io.ReadFull(c, b[:16+2]); err != nil {
			return dst, err
		}
		dst.IP = netip.AddrFrom16([16]byte(b[:16])).Unmap()
		dst.Port = binary.BigEndian.Uint16(b[16:])
	case atypDomain:
		if _, err := io.ReadFull(c, b[:1]); err != nil {
			return dst, err
		}
		n := int(b[0])
		if _, err := io.ReadFull(c, b[:n+2]); err != nil {
			return dst, err
		}
		if n == 0 {
			return dst, errors.New("socks: empty domain")
		}
		dst = addr(string(b[:n]), binary.BigEndian.Uint16(b[n:]))
	default:
		socksReply(c, repAtypNotSupp)
		return dst, errors.New("socks: bad address type")
	}
	if cmd != cmdConnect {
		socksReply(c, repCmdNotSupp)
		return dst, errors.New("socks: command not supported")
	}
	if err := socksReply(c, repSuccess); err != nil {
		return dst, err
	}
	return dst, nil
}

func socksReply(c net.Conn, rep byte) error {
	_, err := c.Write([]byte{socksVer, rep, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
