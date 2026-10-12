// Package client builds an outbound.Dialer from a config.Client by
// stacking: TCP dial -> security layer ("tls" | "reality") -> network
// layer ("ws" | "grpc"; "tcp" = none) -> protocol ("vless" | "vmess").
// Defaults follow Xray: TLS serverName = sni || address, ws Host =
// host || sni || address, grpc authority = authority || sni || address.
//
// Transports and protocols register themselves from build-tagged packages;
// the imports_*.go files here pull in whichever are compiled.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/netguard"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/pool"
	"github.com/onlymaj/v2ray-client-go/internal/transport"
	_ "github.com/onlymaj/v2ray-client-go/internal/transport/tls"
)

const dialTimeout = 10 * time.Second

// streamDialer matches grpc.StreamDialer without importing the
// build-tagged grpc package.
type streamDialer interface {
	DialStream(ctx context.Context, dialRaw func(ctx context.Context) (net.Conn, error)) (net.Conn, error)
}

// Client is a ready-to-use proxy client. Safe for concurrent use.
type Client struct {
	cfg      config.Client
	server   string
	tcp      net.Dialer
	security transport.Layer // nil for "none"
	network  transport.Layer // nil for "tcp"
	stream   streamDialer    // set for grpc: tunnels share one h2 conn
	pool     *pool.Pool      // nil when not pooled (grpc)
	dialer   outbound.Dialer
	probe    outbound.Dialer // same, bypassing the pool
}

// Options carries settings that are not part of the client config.
type Options struct {
	// AllowPrivate lets a client that came from a subscription or from
	// pasted links (config.Client.Untrusted) use a server in a private
	// range (config.Settings.AllowPrivateServers). Clients saved through
	// the form may always do so.
	AllowPrivate bool
}

// refusedServer and isPrivate classify server addresses (vars for tests,
// which run servers on loopback).
var (
	refusedServer = netguard.Refused
	isPrivate     = netguard.Private
)

// serverGuard is a net.Dialer Control that refuses netguard.Refused
// addresses and, with blockPrivate, private ones. It sees the resolved
// address of every attempt, so a hostname cannot rebind around it.
func serverGuard(blockPrivate bool) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if ip := ap.Addr(); refusedServer(ip) || blockPrivate && isPrivate(ip) {
			return fmt.Errorf("server address %s refused", ip)
		}
		return nil
	}
}

// Build validates c and builds its transport stack. No connection is made.
func Build(c config.Client, opts Options) (*Client, error) {
	if c.Address == "" || c.Port == 0 {
		return nil, errors.New("client " + c.ID + ": address and port are required")
	}
	cl := &Client{
		cfg:    c,
		server: net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port))),
		tcp: net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second,
			Control: serverGuard((c.SubscriptionID != "" || c.Untrusted) && !opts.AllowPrivate)},
	}
	sni := c.SNI
	if sni == "" {
		sni = c.Address
	}
	fp := c.Fingerprint
	if fp == "" {
		fp = "chrome"
	}

	var err error
	switch c.TLS {
	case "", "none":
	case "tls":
		alpn := c.ALPN
		switch {
		case c.Network == "grpc" && !slices.Contains(alpn, "h2"):
			alpn = append([]string{"h2"}, alpn...)
		case c.Network == "ws":
			// Always, whatever the config or link says: the WebSocket
			// upgrade is HTTP/1.1 and fails if the server picks h2. Xray
			// forces the same (transport/internet/websocket/dialer.go).
			alpn = []string{"http/1.1"}
		case len(alpn) > 0:
		default:
			alpn = []string{"h2", "http/1.1"}
		}
		cl.security, err = layer("tls", map[string]any{
			"serverName": sni, "fingerprint": fp, "alpn": alpn, "allowInsecure": c.AllowInsecure,
		})
	case "reality":
		cl.security, err = layer("reality", map[string]any{
			"serverName": sni, "fingerprint": fp,
			"publicKey": c.PublicKey, "shortId": c.ShortID, "spiderX": c.SpiderX,
		})
	default:
		err = errors.New("unknown security " + c.TLS)
	}
	if err != nil {
		return nil, wrap(c, err)
	}

	switch c.Network {
	case "", "tcp":
	case "ws":
		host := c.Host
		if host == "" {
			host = sni
		}
		cl.network, err = layer("ws", map[string]any{"path": c.Path, "host": host})
	case "grpc":
		auth := c.Authority
		if auth == "" {
			auth = sni
		}
		cl.network, err = layer("grpc", map[string]any{
			"serviceName": c.ServiceName, "multiMode": c.MultiMode, "authority": auth,
		})
		if sd, ok := cl.network.(streamDialer); ok {
			cl.stream = sd
		}
	default:
		err = errors.New("unknown network " + c.Network)
	}
	if err != nil {
		return nil, wrap(c, err)
	}

	var ps []byte
	switch c.Protocol {
	case "vless":
		ps, _ = json.Marshal(map[string]any{"id": c.UUID, "flow": c.Flow})
	case "vmess":
		// Inside verified TLS or REALITY the chunk nonce may wrap as in
		// Xray: the outer AEAD protects the stream (see
		// vmess.Settings.AllowNonceWrap). TLS with allowInsecure does not
		// count: an on-path attacker could terminate it.
		wrapOK := c.TLS == "reality" || c.TLS == "tls" && !c.AllowInsecure
		ps, _ = json.Marshal(map[string]any{"id": c.UUID, "security": c.Security,
			"allowNonceWrap": wrapOK})
	default:
		return nil, wrap(c, errors.New("unknown protocol "+c.Protocol))
	}
	f, err := outbound.Lookup(c.Protocol)
	if err != nil {
		return nil, wrap(c, err)
	}
	if c.Network != "grpc" { // grpc reuses its h2 conn instead
		cl.pool = pool.New(cl.dialTransport)
	}
	if cl.dialer, err = f(ps, cl.transport); err != nil {
		cl.Close()
		return nil, wrap(c, err)
	}
	cl.probe = cl.dialer
	if cl.pool != nil {
		if cl.probe, err = f(ps, cl.dialTransport); err != nil {
			cl.Close()
			return nil, wrap(c, err)
		}
	}
	return cl, nil
}

func layer(name string, settings map[string]any) (transport.Layer, error) {
	f, err := transport.Lookup(name)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return f(b)
}

func wrap(c config.Client, err error) error {
	return errors.New("client " + c.ID + ": " + err.Error())
}

// dialRaw opens TCP to the server and applies the security layer.
func (c *Client) dialRaw(ctx context.Context) (net.Conn, error) {
	conn, err := c.tcp.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return nil, err
	}
	if c.security == nil {
		return conn, nil
	}
	sc, err := c.security.Wrap(ctx, conn)
	if err != nil {
		if !errors.Is(err, transport.ErrConnKept) {
			conn.Close()
		}
		return nil, err
	}
	return sc, nil
}

// dialTransport opens a full, unpooled transport conn.
func (c *Client) dialTransport(ctx context.Context) (net.Conn, error) {
	if c.stream != nil {
		return c.stream.DialStream(ctx, c.dialRaw)
	}
	conn, err := c.dialRaw(ctx)
	if err != nil || c.network == nil {
		return conn, err
	}
	nc, err := c.network.Wrap(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return nc, nil
}

// reusedKey carries a *bool through the protocol's Dial so transport can
// report whether it handed out a warm pooled conn.
type reusedKey struct{}

// transport is what the protocol layer calls: pooled when possible.
func (c *Client) transport(ctx context.Context) (net.Conn, error) {
	if c.pool == nil {
		return c.dialTransport(ctx)
	}
	conn, reused, err := c.pool.Get(ctx)
	if p, ok := ctx.Value(reusedKey{}).(*bool); ok {
		*p = reused
	}
	return conn, err
}

// Dial opens a proxied connection to dest. If it rides on a warm pooled
// transport conn that turns out to be dead, it is retried once on a fresh
// dial: immediately if the protocol Dial fails, else on first use (see
// retryConn).
func (c *Client) Dial(ctx context.Context, network string, dest outbound.Addr) (net.Conn, error) {
	if c.pool == nil {
		return c.dialer.Dial(ctx, network, dest)
	}
	var reused bool
	conn, err := c.dialer.Dial(context.WithValue(ctx, reusedKey{}, &reused), network, dest)
	if !reused {
		return conn, err
	}
	if err != nil {
		return c.probe.Dial(ctx, network, dest)
	}
	return newRetryConn(conn, func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		return c.probe.Dial(ctx, network, dest)
	}), nil
}

// Probe is Dial without the warm pool, for health checks: it neither uses
// nor triggers pre-dialed conns, so probes do not count as traffic.
func (c *Client) Probe(ctx context.Context, network string, dest outbound.Addr) (net.Conn, error) {
	return c.probe.Dial(ctx, network, dest)
}

// DialServer measures a plain TCP connect to the server.
func (c *Client) DialServer(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	conn, err := c.tcp.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return 0, err
	}
	d := time.Since(start)
	conn.Close()
	return d, nil
}

// Server returns host:port of the proxy server.
func (c *Client) Server() string { return c.server }

// Config returns the config the client was built from.
func (c *Client) Config() config.Client { return c.cfg }

// Close releases idle pooled conns and the shared gRPC connection.
// In-flight proxied connections are not affected (except gRPC streams).
func (c *Client) Close() {
	if c.pool != nil {
		c.pool.Close()
	}
	if cl, ok := c.network.(interface{ Close() error }); ok {
		cl.Close()
	}
}

// SameTransport reports whether a and b build identical clients (fields
// that only label the client, like Name or Enabled, are ignored).
func SameTransport(a, b config.Client) bool {
	a.Name, a.Enabled, a.SubscriptionID = "", false, ""
	b.Name, b.Enabled, b.SubscriptionID = "", false, ""
	if len(a.ALPN) == 0 && len(b.ALPN) == 0 {
		a.ALPN, b.ALPN = nil, nil
	}
	return reflect.DeepEqual(a, b)
}
