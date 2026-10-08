package client

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/transport"
)

// captureLayer records its settings and passes conns through.
type captureLayer struct{ settings map[string]any }

func (l *captureLayer) Wrap(ctx context.Context, c net.Conn) (net.Conn, error) { return c, nil }

// fakeLayers replaces the named transports with capturing pass-through
// layers for the duration of the test.
func fakeLayers(t *testing.T, names ...string) map[string]*captureLayer {
	got := map[string]*captureLayer{}
	for _, n := range names {
		orig, origErr := transport.Lookup(n)
		transport.Register(n, func(b []byte) (transport.Layer, error) {
			l := &captureLayer{}
			json.Unmarshal(b, &l.settings)
			got[n] = l
			return l, nil
		})
		t.Cleanup(func() {
			if origErr == nil {
				transport.Register(n, orig)
			}
		})
	}
	return got
}

// echoProto is a fake protocol: it opens a transport conn and writes the
// destination as a line before passing data through.
type echoProto struct {
	dial func(ctx context.Context) (net.Conn, error)
}

func (p *echoProto) Dial(ctx context.Context, _ string, dest outbound.Addr) (net.Conn, error) {
	c, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.Write([]byte(dest.String() + "\n"))
	return c, nil
}

func fakeProtocol(t *testing.T, name string) {
	orig, origErr := outbound.Lookup(name)
	outbound.Register(name, func(_ []byte, d func(ctx context.Context) (net.Conn, error)) (outbound.Dialer, error) {
		return &echoProto{dial: d}, nil
	})
	t.Cleanup(func() {
		if origErr == nil {
			outbound.Register(name, orig)
		}
	})
}

func base() config.Client {
	return config.Client{ID: "c1", Protocol: "vless", Address: "example.com", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555", Network: "tcp", TLS: "tls"}
}

func TestDefaults(t *testing.T) {
	fakeProtocol(t, "vless")
	got := fakeLayers(t, "tls", "ws", "grpc")
	cases := []struct {
		name    string
		mod     func(*config.Client)
		alpn    []any
		netName string
		netKey  string
		netVal  string
	}{
		{"tcp", func(c *config.Client) {}, []any{"h2", "http/1.1"}, "", "", ""},
		{"ws", func(c *config.Client) { c.Network = "ws" }, []any{"http/1.1"}, "ws", "host", "example.com"},
		{"ws host", func(c *config.Client) { c.Network, c.SNI, c.Host = "ws", "sni.test", "h.test" },
			[]any{"http/1.1"}, "ws", "host", "h.test"},
		{"ws sni", func(c *config.Client) { c.Network, c.SNI = "ws", "sni.test" },
			[]any{"http/1.1"}, "ws", "host", "sni.test"},
		{"grpc", func(c *config.Client) { c.Network, c.SNI = "grpc", "sni.test" }, []any{"h2"}, "grpc", "authority", "sni.test"},
		{"grpc forced h2", func(c *config.Client) { c.Network, c.ALPN = "grpc", []string{"http/1.1"} },
			[]any{"h2", "http/1.1"}, "grpc", "authority", "example.com"},
		{"explicit alpn", func(c *config.Client) { c.ALPN = []string{"http/1.1"} }, []any{"http/1.1"}, "", "", ""},
	}
	for _, tc := range cases {
		clear(got)
		c := base()
		tc.mod(&c)
		cl, err := Build(c)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		tl := got["tls"].settings
		wantSNI := c.SNI
		if wantSNI == "" {
			wantSNI = c.Address
		}
		if tl["serverName"] != wantSNI || tl["fingerprint"] != "chrome" {
			t.Errorf("%s: tls settings %v", tc.name, tl)
		}
		if a, _ := json.Marshal(tl["alpn"]); string(a) != mustJSON(tc.alpn) {
			t.Errorf("%s: alpn %s, want %s", tc.name, a, mustJSON(tc.alpn))
		}
		if tc.netName != "" {
			if v := got[tc.netName].settings[tc.netKey]; v != tc.netVal {
				t.Errorf("%s: %s=%v, want %s", tc.name, tc.netKey, v, tc.netVal)
			}
		}
		if (cl.pool == nil) != (c.Network == "grpc") {
			t.Errorf("%s: pool=%v", tc.name, cl.pool != nil)
		}
		cl.Close()
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestBuildErrors(t *testing.T) {
	fakeProtocol(t, "vless")
	for _, mod := range []func(*config.Client){
		func(c *config.Client) { c.Network = "quic" },
		func(c *config.Client) { c.TLS = "xtls" },
		func(c *config.Client) { c.Protocol = "trojan" },
		func(c *config.Client) { c.Port = 0 },
	} {
		c := base()
		mod(&c)
		if _, err := Build(c); err == nil {
			t.Errorf("Build(%+v) succeeded", c)
		}
	}
}

func TestDialThroughStack(t *testing.T) {
	fakeProtocol(t, "vless")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	c := base()
	c.Address, c.Port, c.TLS = "127.0.0.1", uint16(port), "none"
	cl, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, dial := range []func(context.Context, string, outbound.Addr) (net.Conn, error){cl.Dial, cl.Probe} {
		conn, err := dial(ctx, "tcp", outbound.Addr{Domain: "x.test", Port: 80})
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len("x.test:80\n"))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "x.test:80\n" {
			t.Fatalf("read %q %v", buf, err)
		}
		conn.Close()
	}
	if d, err := cl.DialServer(ctx); err != nil || d <= 0 {
		t.Fatalf("DialServer %v %v", d, err)
	}
	if cl.Server() != ln.Addr().String() {
		t.Fatalf("Server() = %s", cl.Server())
	}
}

func TestSameTransport(t *testing.T) {
	a, b := base(), base()
	b.Name, b.Enabled = "other", true
	if !SameTransport(a, b) {
		t.Fatal("label-only change reported as different")
	}
	b.ALPN = []string{}
	if !SameTransport(a, b) {
		t.Fatal("nil vs empty ALPN reported as different")
	}
	b.ALPN = []string{"h2"}
	if SameTransport(a, b) {
		t.Fatal("ALPN change not detected")
	}
}

// Warm pooled conns that the server dropped are replaced transparently on
// first use, with the written data replayed.
func TestRetryDeadPooledConn(t *testing.T) {
	fakeProtocol(t, "vless")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				// Drop conns that stay silent (idle pooled ones).
				c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				b := make([]byte, 1)
				if _, err := c.Read(b); err != nil {
					c.Close()
					return
				}
				c.SetReadDeadline(time.Time{})
				c.Write(b)
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	c := base()
	c.Address, c.Port, c.TLS = "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port), "none"
	cl, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx := context.Background()
	dest := outbound.Addr{Domain: "x.test", Port: 80}
	for i := 0; i < 2; i++ { // two dials: the client is busy, the pool warms
		conn, err := cl.Dial(ctx, "tcp", dest)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for cl.pool.Len() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cl.pool.Len() < 2 {
		t.Fatal("pool did not warm")
	}
	time.Sleep(150 * time.Millisecond) // server drops the idle conns

	conn, err := cl.Dial(ctx, "tcp", dest)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*retryConn); !ok {
		t.Fatalf("pooled dial not wrapped: %T", conn)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("ping"))
	want := "x.test:80\nping"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
}
