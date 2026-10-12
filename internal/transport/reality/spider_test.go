//go:build reality

package reality

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/transport"
)

// Round 11: when a dial reached the real camouflage site, Wrap started the
// browser-like fetch and returned an error; the caller then closed the conn
// under it, so the request was never sent and every such dial showed a
// handshake followed by an instant close. Wrap now says it kept the conn.
func TestSpiderKeepsConn(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Method + " " + r.URL.Path:
		default:
		}
	}))
	defer srv.Close()
	roots = x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	defer func() { roots = nil }()
	settings, _ := json.Marshal(Settings{ServerName: "example.com", Fingerprint: "chrome",
		PublicKey: base64.RawURLEncoding.EncodeToString(fixedKey(t, 1).PublicKey().Bytes()), SpiderX: "/page"})
	l, err := New(settings)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = l.Wrap(ctx, conn); !errors.Is(err, transport.ErrConnKept) {
		t.Fatalf("Wrap against a real certificate: %v, want an error wrapping ErrConnKept", err)
	}
	select {
	case req := <-got:
		if req != "GET /page" {
			t.Fatalf("spider sent %q", req)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fallback request never reached the site")
	}
}
