// Package transport defines the Layer interface (TLS, Reality, WebSocket,
// gRPC, ...) that wraps a raw TCP connection to the proxy server, plus a
// registry populated by build-tagged init() functions.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

// Layer wraps conn (already connected to the proxy server) and returns the
// connection the protocol layer writes to. Layers stack: tcp -> tls -> ws.
type Layer interface {
	Wrap(ctx context.Context, conn net.Conn) (net.Conn, error)
}

// ErrConnKept is wrapped by a Wrap error when the layer still uses conn and
// closes it itself (Reality's fallback fetch). The caller must not close it.
var ErrConnKept = errors.New("transport: connection kept by the layer")

// Factory builds a Layer from its settings blob (the client's JSON config
// for that layer).
type Factory func(settings []byte) (Layer, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	factories[name] = f
}

func Lookup(name string) (Factory, error) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := factories[name]
	if !ok {
		return nil, fmt.Errorf("transport %q not compiled in", name)
	}
	return f, nil
}

type sourceKey struct{}

// WithSource names whose traffic a dial is for (the LAN device's address).
// A layer that shares limits between tunnels can use it to make a device
// pay for its own excess rather than another's.
func WithSource(ctx context.Context, src string) context.Context {
	return context.WithValue(ctx, sourceKey{}, src)
}

// Source returns the name given to WithSource, or "".
func Source(ctx context.Context) string {
	src, _ := ctx.Value(sourceKey{}).(string)
	return src
}

// ChromeUA is the User-Agent the HTTP transports send by default, as Xray
// does (common/utils/browser.go): the TLS hello under them is Chrome's.
const ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
