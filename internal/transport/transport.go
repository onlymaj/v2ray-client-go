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
