// Package tls is the "tls" transport layer: a uTLS client that mimics a
// browser ClientHello. Mirrors transport/internet/tls in Xray (UClient,
// GetFingerprint, WebsocketHandshakeContext for the ALPN rewrite).
package tls

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"net"

	utls "github.com/refraction-networking/utls"
	// The container is FROM scratch with no /etc/ssl: crypto/x509 falls back
	// to this bundled Mozilla root set when the system has no roots.
	_ "golang.org/x/crypto/x509roots/fallback"

	"github.com/onlymaj/v2ray-client-go/internal/transport"
)

type Settings struct {
	ServerName    string   `json:"serverName"`
	Fingerprint   string   `json:"fingerprint"` // chrome (default) | firefox | safari | random
	ALPN          []string `json:"alpn"`
	AllowInsecure bool     `json:"allowInsecure"`
}

type layer struct {
	s  Settings
	id utls.ClientHelloID
}

func init() {
	transport.Register("tls", func(settings []byte) (transport.Layer, error) {
		var s Settings
		if len(settings) > 0 {
			if err := json.Unmarshal(settings, &s); err != nil {
				return nil, err
			}
		}
		// Resolved once per client: "random" must not change browser from
		// one connection to the next, which no real browser does.
		id, err := Fingerprint(s.Fingerprint)
		if err != nil {
			return nil, err
		}
		return &layer{s, id}, nil
	})
}

// Fingerprint maps a config name to a uTLS ClientHelloID (subset of
// PresetFingerprints in Xray's transport/internet/tls/tls.go).
func Fingerprint(name string) (utls.ClientHelloID, error) {
	switch name {
	case "", "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "random":
		// Like Xray's "random" preset: one of the browser fingerprints.
		// (utls.HelloRandomized may offer only TLS 1.2, which breaks
		// REALITY and Vision.)
		return [...]utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto,
			utls.HelloSafari_Auto}[rand.IntN(3)], nil
	}
	return utls.ClientHelloID{}, errors.New("tls: unknown fingerprint " + name)
}

// ServerNameOr returns name, or the host of conn's remote address when name
// is empty (Xray falls back to the destination address the same way).
func ServerNameOr(name string, conn net.Conn) string {
	if name != "" {
		return name
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func (l *layer) Wrap(ctx context.Context, conn net.Conn) (net.Conn, error) {
	id := l.id
	rec := NewRecordConn(conn)
	u := utls.UClient(rec, &utls.Config{
		ServerName:         ServerNameOr(l.s.ServerName, conn),
		InsecureSkipVerify: l.s.AllowInsecure,
		// RootCAs nil: system roots, else x509roots/fallback.
	}, id)
	if len(l.s.ALPN) > 0 {
		if err := setALPN(u, l.s.ALPN); err != nil {
			return nil, err
		}
	}
	rec.SetLimit(MaxHandshakeIn)
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return NewConn(u, rec), nil
}

// setALPN builds the fingerprint's hello, rewrites (or appends) its ALPN
// extension and rebuilds it. Same as Xray's WebsocketHandshakeContext. The
// second BuildHandshakeState keeps the already generated key shares.
func setALPN(u *utls.UConn, alpn []string) error {
	if err := u.BuildHandshakeState(); err != nil {
		return err
	}
	found := false
	for _, ext := range u.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = alpn
			found = true
			break
		}
	}
	if !found {
		u.Extensions = append(u.Extensions, &utls.ALPNExtension{AlpnProtocols: alpn})
	}
	return u.BuildHandshakeState()
}

// Conn is the connection returned by the tls and reality layers.
// ConnectionState (embedded from utls.UConn) and NegotiatedProtocol expose
// the ALPN result (the gRPC transport needs "h2"); TLSVersion, DirectReader
// and DirectWriter are what VLESS Vision needs to bypass the outer TLS.
type Conn struct {
	*utls.UConn
	rec *RecordConn
}

// NewConn is called once the handshake is done.
func NewConn(u *utls.UConn, rec *RecordConn) *Conn {
	rec.SetLimit(MaxQuietIn)
	return &Conn{UConn: u, rec: rec}
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.UConn.Read(p)
	if n > 0 {
		c.rec.Progress()
	}
	return n, err
}

func (c *Conn) NegotiatedProtocol() string { return c.ConnectionState().NegotiatedProtocol }

func (c *Conn) TLSVersion() uint16 { return c.ConnectionState().Version }

// DirectReader returns the raw stream below TLS, starting right after the
// last TLS record uTLS has consumed. Only call it once uTLS reads stop.
func (c *Conn) DirectReader() io.Reader {
	c.rec.SetRaw()
	return c.rec
}

// DirectWriter returns the raw TCP connection below TLS.
func (c *Conn) DirectWriter() io.Writer { return c.rec.Conn }

// NetConn returns the raw TCP connection (closing it skips close_notify).
func (c *Conn) NetConn() net.Conn { return c.rec.Conn }
