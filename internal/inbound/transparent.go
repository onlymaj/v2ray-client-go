package inbound

import (
	"context"
	"net"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// ServeTransparent serves connections REDIRECTed by netfilter: the
// destination is the conntrack original destination. Connections made to
// the listener itself (not redirected) are dropped to avoid loops.
func ServeTransparent(ctx context.Context, ln net.Listener, h Handler) error {
	return serve(ctx, ln, func(c net.Conn) {
		tc, ok := c.(*net.TCPConn)
		if !ok {
			c.Close()
			return
		}
		dst, err := OriginalDst(tc)
		if err != nil {
			c.Close()
			return
		}
		local := tc.LocalAddr().(*net.TCPAddr).AddrPort()
		if dst.Addr() == local.Addr().Unmap() && dst.Port() == local.Port() {
			c.Close()
			return
		}
		h.Handle(c, srcOf(c), outbound.Addr{IP: dst.Addr(), Port: dst.Port()}, true)
	})
}
