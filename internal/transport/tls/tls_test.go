package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/transport"
)

func selfSigned(t *testing.T) gotls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve accepts one TLS conn, writes "hello" through TLS and then "RAW"
// directly on TCP, the way an Xray server switches to Vision direct mode.
func serve(t *testing.T, ln net.Listener, cert gotls.Certificate) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	s := gotls.Server(c, &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := s.Handshake(); err != nil {
		return // TestVerifyFails
	}
	s.Write([]byte("hello"))
	c.Write([]byte("RAW"))
	io.Copy(io.Discard, c)
}

func dial(t *testing.T, settings string) (*Conn, net.Listener) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serve(t, ln, selfSigned(t))
	f, err := transport.Lookup("tls")
	if err != nil {
		t.Fatal(err)
	}
	l, err := f([]byte(settings))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := l.Wrap(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Conn), ln
}

func TestALPNAndDirect(t *testing.T) {
	for _, tc := range []struct{ settings, want string }{
		{`{"serverName":"example.test","allowInsecure":true,"alpn":["h2"]}`, "h2"},
		{`{"serverName":"example.test","allowInsecure":true,"alpn":["http/1.1"],"fingerprint":"firefox"}`, "http/1.1"},
		{`{"serverName":"example.test","allowInsecure":true,"alpn":["http/1.1"],"fingerprint":"random"}`, "http/1.1"},
	} {
		c, ln := dial(t, tc.settings)
		if got := c.NegotiatedProtocol(); got != tc.want {
			t.Errorf("%s: ALPN %q, want %q", tc.settings, got, tc.want)
		}
		if c.TLSVersion() != gotls.VersionTLS13 {
			t.Errorf("version %x", c.TLSVersion())
		}
		buf := make([]byte, 8192)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != "hello" {
			t.Fatalf("tls read %q %v", buf[:n], err)
		}
		// "RAW" most likely arrived in the same TCP segment; RecordConn must
		// have kept it out of uTLS.
		n, err = io.ReadFull(c.DirectReader(), buf[:3])
		if err != nil || string(buf[:n]) != "RAW" {
			t.Fatalf("direct read %q %v", buf[:n], err)
		}
		c.Close()
		ln.Close()
	}
}

func TestVerifyFails(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go serve(t, ln, selfSigned(t))
	f, _ := transport.Lookup("tls")
	l, _ := f([]byte(`{"serverName":"example.test"}`))
	raw, _ := net.Dial("tcp", ln.Addr().String())
	if _, err := l.Wrap(context.Background(), raw); err == nil {
		t.Fatal("self-signed cert accepted without allowInsecure")
	}
}

func TestRecordConnFraming(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		// two records (one empty) and trailing raw bytes in one write
		b.Write([]byte{0x17, 3, 3, 0, 2, 'h', 'i', 0x17, 3, 3, 0, 0, 'r', 'a', 'w'})
		b.Close()
	}()
	rc := NewRecordConn(a)
	buf := make([]byte, 64)
	var got []int
	for _, want := range []int{5, 2, 5} {
		n, err := rc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
		if n != want {
			t.Fatalf("read sizes %v", got)
		}
	}
	rc.SetRaw()
	n, _ := rc.Read(buf)
	if string(buf[:n]) != "raw" {
		t.Fatalf("raw %q", buf[:n])
	}
}

// Round 12: fingerprint "random" was drawn again for every connection, so
// one client showed Chrome, Firefox and Safari hellos to the same server
// seconds apart. It is drawn once per client, as in Xray.
func TestRandomFingerprintStablePerLayer(t *testing.T) {
	f, err := transport.Lookup("tls")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 40 {
		l, err := f([]byte(`{"fingerprint":"random"}`))
		if err != nil {
			t.Fatal(err)
		}
		tl := l.(*layer)
		if tl.id.Client == "" {
			t.Fatal("no fingerprint stored in the layer")
		}
		seen[tl.id.Client] = true
	}
	if len(seen) < 2 {
		t.Fatalf("random always picked %v", seen)
	}
}
