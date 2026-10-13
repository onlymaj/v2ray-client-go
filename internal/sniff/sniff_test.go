package sniff

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
)

// clientHello captures the first TLS record a crypto/tls client sends.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() {
		cl := tls.Client(c1, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
		cl.Handshake()
		c1.Close()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func TestSNI(t *testing.T) {
	hello := clientHello(t, "WWW.Example.COM")
	got, err := SNI(hello)
	if err != nil || got != "www.example.com" {
		t.Fatalf("SNI = %q, %v", got, err)
	}
	if d, proto, err := Sniff(hello); d != "www.example.com" || proto != "tls" || err != nil {
		t.Errorf("Sniff = %q %q %v", d, proto, err)
	}
	// Every strict prefix must ask for more data.
	for i := 0; i < len(hello); i++ {
		if _, err := SNI(hello[:i]); !errors.Is(err, ErrNeedMore) {
			t.Fatalf("SNI(hello[:%d]) err = %v, want ErrNeedMore", i, err)
		}
	}
	// Trailing application data after the record is ignored.
	if got, _ := SNI(append(hello, 0x17, 3, 3, 0, 1, 0)); got != "www.example.com" {
		t.Errorf("SNI with trailing data = %q", got)
	}
}

func TestSNIAbsent(t *testing.T) {
	// crypto/tls omits SNI for IP server names.
	hello := clientHello(t, "192.0.2.1")
	if _, err := SNI(hello); !errors.Is(err, ErrNoDomain) {
		t.Errorf("err = %v, want ErrNoDomain", err)
	}
}

func TestSNIMalformed(t *testing.T) {
	for _, b := range [][]byte{
		{0x17, 3, 3, 0, 5},                   // not handshake
		{0x16, 2, 0},                         // bad version
		{0x16, 3, 1, 0x50, 0x00},             // record too large
		{0x16, 3, 1, 0, 4, 2, 0, 0, 0},       // server_hello
		{0x16, 3, 1, 0, 6, 1, 0, 0, 2, 3, 3}, // body too short
	} {
		if _, err := SNI(b); !errors.Is(err, ErrNotTLS) {
			t.Errorf("SNI(% x) err = %v, want ErrNotTLS", b, err)
		}
	}
}

func TestHTTPHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  error
	}{
		{"GET / HTTP/1.1\r\nHost: Example.com\r\n\r\n", "example.com", nil},
		{"POST /x HTTP/1.1\r\nUser-Agent: a\r\nhost:  example.org:8080 \r\n", "example.org", nil},
		{"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n", "", ErrNoDomain},
		{"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n", "", ErrNoDomain},
		{"GET / HTTP/1.0\r\nAccept: */*\r\n\r\n", "", ErrNoDomain},
		{"GET / HTTP/1.1\r\nAccept: */*\r\nHo", "", ErrNeedMore},
		{"GET / HTTP/1.1\r\nHost: example.com", "", ErrNeedMore},
		{"GET /index", "", ErrNeedMore},
		{"DEL", "", ErrNeedMore},
		{"", "", ErrNeedMore},
		{"SSH-2.0-OpenSSH_9.6\r\n", "", ErrNotHTTP},
		{"get / HTTP/1.1\r\n", "", ErrNotHTTP},
	}
	for _, tt := range tests {
		got, err := HTTPHost([]byte(tt.in))
		if got != tt.want || !errors.Is(err, tt.err) {
			t.Errorf("HTTPHost(%q) = %q, %v; want %q, %v", tt.in, got, err, tt.want, tt.err)
		}
	}
	if d, proto, err := Sniff([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n")); d != "a.example" || proto != "http" || err != nil {
		t.Errorf("Sniff http = %q %q %v", d, proto, err)
	}
	if _, proto, err := Sniff([]byte("SSH-2.0\r\n")); proto != "" || !errors.Is(err, ErrNotHTTP) {
		t.Errorf("Sniff ssh = %q %v", proto, err)
	}
}

func BenchmarkSNI(b *testing.B) {
	hello := clientHello(&testing.T{}, "www.example.com")
	b.ReportAllocs()
	for b.Loop() {
		SNI(hello)
	}
}

// Round 23: a ClientHello longer than the 4 KiB that are sniffed was never
// parsed, so its connection missed the domain rules. The name is found in
// a record that is cut short, if it lies before the cut.
func TestSNIPrefix(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	if _, err := SNI(hello[:len(hello)-1]); err != ErrNeedMore {
		t.Fatalf("SNI of an incomplete record: %v, want ErrNeedMore", err)
	}
	at := bytes.Index(hello, []byte("www.example.com"))
	if at < 0 {
		t.Fatal("no name in the hello")
	}
	end := at + len("www.example.com")
	if got, err := SNIPrefix(hello[:end]); err != nil || got != "www.example.com" {
		t.Fatalf("name within the prefix: %q, %v", got, err)
	}
	for _, cut := range []int{6, 44, at, end - 1} {
		if got, err := SNIPrefix(hello[:cut]); err == nil {
			t.Fatalf("prefix of %d bytes gave %q, want an error", cut, got)
		}
	}
}
