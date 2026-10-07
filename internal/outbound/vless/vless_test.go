//go:build vless

package vless

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

var testID, _ = ParseUUID(testUUID)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func TestRequestHeader(t *testing.T) {
	uuid := "b831381d63244d53ad4f8cda48b30811"
	for _, tc := range []struct {
		flow string
		dest outbound.Addr
		want string
	}{
		{"", outbound.Addr{Domain: "example.com", Port: 443},
			"00" + uuid + "00 01 01bb 02 0b 6578616d706c652e636f6d"},
		{"", outbound.Addr{IP: netip.MustParseAddr("1.2.3.4"), Port: 80},
			"00" + uuid + "00 01 0050 01 01020304"},
		{"", outbound.Addr{IP: netip.MustParseAddr("::ffff:1.2.3.4"), Port: 80},
			"00" + uuid + "00 01 0050 01 01020304"},
		{"", outbound.Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 8080},
			"00" + uuid + "00 01 1f90 03 20010db8000000000000000000000001"},
		// addons: len 18 | 0a (field 1, bytes) | 10 (16) | "xtls-rprx-vision"
		{FlowVision, outbound.Addr{Domain: "a.b", Port: 1},
			"00" + uuid + "12 0a 10 78746c732d727072782d766973696f6e 01 0001 02 03 612e62"},
	} {
		got, err := EncodeRequestHeader(testID, tc.flow, tc.dest)
		if err != nil {
			t.Fatal(err)
		}
		if want := unhex(tc.want); !bytes.Equal(got, want) {
			t.Errorf("%v:\n got %x\nwant %x", tc.dest, got, want)
		}
	}
}

func TestParseUUID(t *testing.T) {
	if hex.EncodeToString(testID[:]) != "b831381d63244d53ad4f8cda48b30811" {
		t.Fatal(testID)
	}
	for _, bad := range []string{"", "b831381d63244d53ad4f8cda48b30811", "z831381d-6324-4d53-ad4f-8cda48b30811"} {
		if _, err := ParseUUID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestResponseHeader(t *testing.T) {
	r := bytes.NewReader([]byte{0, 0, 'x'})
	if err := DecodeResponseHeader(r); err != nil || r.Len() != 1 {
		t.Fatal(err, r.Len())
	}
	r = bytes.NewReader([]byte{0, 2, 0x0a, 0x00, 'x'})
	if err := DecodeResponseHeader(r); err != nil || r.Len() != 1 {
		t.Fatal("addons not skipped", err, r.Len())
	}
	if err := DecodeResponseHeader(bytes.NewReader([]byte{1, 0})); err == nil {
		t.Fatal("bad version accepted")
	}
	if err := DecodeResponseHeader(bytes.NewReader([]byte{0, 5, 1})); err == nil {
		t.Fatal("short addons accepted")
	}
}

// fakeConn is a net.Conn + directConn over in-memory buffers. Reads come
// from in (the "TLS" stream) then raw after DirectReader; writes go to out
// (TLS) or rawOut (direct).
type fakeConn struct {
	net.Conn
	in, raw     io.Reader
	out, rawOut bytes.Buffer
}

func (f *fakeConn) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeConn) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeConn) Close() error                { return nil }
func (f *fakeConn) TLSVersion() uint16          { return 0x0304 }
func (f *fakeConn) DirectReader() io.Reader     { return f.raw }
func (f *fakeConn) DirectWriter() io.Writer     { return &f.rawOut }

// readAll unpads stream with a fresh downlink state.
func unpadAll(t *testing.T, stream []byte) []byte {
	f := &fakeConn{in: bytes.NewReader(stream), raw: bytes.NewReader(nil)}
	v := newVision(f, f, testID)
	got, err := io.ReadAll(readerFunc(v.read))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestPaddingRoundTrip(t *testing.T) {
	f := &fakeConn{}
	v := newVision(f, f, testID)
	header := []byte("HDR")
	payload := bytes.Repeat([]byte("plain text, not TLS "), 1000) // 20000 bytes
	if _, err := v.write(header, payload[:100]); err != nil {
		t.Fatal(err)
	}
	for i := 100; i < len(payload); i += 1000 {
		if _, err := v.write(nil, payload[i:min(i+1000, len(payload))]); err != nil {
			t.Fatal(err)
		}
	}
	stream := f.out.Bytes()
	if !bytes.HasPrefix(stream, header) || !bytes.Equal(stream[3:19], testID[:]) {
		t.Fatalf("stream must start with header then uuid: %x", stream[:24])
	}
	// first block: cmd continue, content 100, short padding (not TLS)
	if stream[19] != cmdPaddingContinue || stream[20] != 0 || stream[21] != 100 {
		t.Fatalf("first block header %x", stream[19:24])
	}
	if pad := int(stream[22])<<8 | int(stream[23]); pad >= 256 {
		t.Fatalf("short padding %d", pad)
	}
	if got := unpadAll(t, stream[3:]); !bytes.Equal(got, payload) {
		t.Fatalf("round trip: got %d bytes, want %d", len(got), len(payload))
	}
	if v.s.isPadding {
		t.Fatal("non-TLS traffic must stop padding after the filter window")
	}
}

func TestPaddingOnlyBlock(t *testing.T) {
	f := &fakeConn{}
	v := newVision(f, f, testID)
	v.write([]byte{0xaa}, nil)
	b := f.out.Bytes()
	if b[0] != 0xaa || !bytes.Equal(b[1:17], testID[:]) || b[17] != 0 || b[18] != 0 || b[19] != 0 {
		t.Fatalf("%x", b[:22])
	}
	if pad := int(b[20])<<8 | int(b[21]); pad < 900 || pad >= 1400 || len(b) != 22+pad {
		t.Fatalf("padding %d, len %d", pad, len(b))
	}
	if got := unpadAll(t, b[1:]); len(got) != 0 {
		t.Fatalf("content %x", got)
	}
}

// serverHello13 is a minimal TLS 1.3 ServerHello record with cipher 0x1301
// and the supported_versions extension.
func serverHello13() []byte {
	body := []byte{0x02, 0, 0, 0, 0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 32)                  // session id len
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x13, 0x01, 0x00) // cipher, compression
	body = append(body, 0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	rec := []byte{0x16, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}
	return append(rec, body...)
}

// block builds one Vision padding block by hand.
func block(cmd byte, content []byte, padding int) []byte {
	b := []byte{cmd, byte(len(content) >> 8), byte(len(content)), byte(padding >> 8), byte(padding)}
	b = append(b, content...)
	return append(b, make([]byte, padding)...)
}

// TestDirectDownlink: the server pads the inner ServerHello, then an
// application data record with cmd 2, then continues raw on TCP.
func TestDirectDownlink(t *testing.T) {
	sh := serverHello13()
	app := []byte{0x17, 0x03, 0x03, 0x00, 0x03, 'a', 'b', 'c'}
	var stream []byte
	stream = append(stream, testID[:]...)
	stream = append(stream, block(cmdPaddingContinue, sh, 300)...)
	stream = append(stream, block(cmdPaddingDirect, app, 10)...)
	raw := []byte("raw inner tls records")
	f := &fakeConn{in: bytes.NewReader(stream), raw: bytes.NewReader(raw)}
	v := newVision(f, f, testID)
	got, err := io.ReadAll(readerFunc(v.read))
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(append([]byte(nil), sh...), app...), raw...)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if !v.s.enableXtls || !v.s.readerDirect {
		t.Fatalf("enableXtls %v readerDirect %v", v.s.enableXtls, v.s.readerDirect)
	}

	// The uplink now ends padding with cmd 2 on the first complete
	// application data write and goes direct afterwards.
	v.s.isTLS = true
	v.write(nil, app)
	out := f.out.Bytes()
	if out[16] != cmdPaddingDirect || !bytes.Equal(out[21:21+len(app)], app) {
		t.Fatalf("uplink block %x", out[:21+len(app)])
	}
	v.write(nil, []byte("next"))
	if f.rawOut.String() != "next" {
		t.Fatalf("direct write %q", f.rawOut.String())
	}
}

func TestIsCompleteRecord(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{"170303000161", true},
		{"170303000161 17030300026162", true},
		{"1703030002 61", false},
		{"170303000061", false},
		{"160303000161", false},
		{"170303", false},
	} {
		if got := isCompleteRecord(unhex(tc.in)); got != tc.want {
			t.Errorf("%s: %v", tc.in, got)
		}
	}
}

func TestReshape(t *testing.T) {
	b := make([]byte, bufSize)
	copy(b[5000:], tlsApplicationDataStart)
	mb := reshape([][]byte{b, []byte("x")})
	if len(mb) != 3 || len(mb[0]) != 5000 || len(mb[1]) != bufSize-5000 {
		t.Fatalf("%d %d", len(mb), len(mb[0]))
	}
	mb = reshape([][]byte{make([]byte, bufSize)})
	if len(mb) != 2 || len(mb[0]) != bufSize/2 {
		t.Fatal("half split")
	}
}

// TestConnHeaderTiming: with no Write within 500ms, the first Read sends
// the header alone (as Xray does) and then parses the response header.
func TestConnHeaderTiming(t *testing.T) {
	a, b := net.Pipe()
	d := &dialer{id: testID, dial: nil}
	header, _ := EncodeRequestHeader(d.id, "", outbound.Addr{Domain: "x", Port: 1})
	c := &conn{Conn: a, header: header, sent: make(chan struct{})}
	go func() {
		got := make([]byte, len(header))
		io.ReadFull(b, got)
		if !bytes.Equal(got, header) {
			t.Error("header")
		}
		b.Write([]byte{0, 0, 'o', 'k'})
	}()
	start := time.Now()
	buf := make([]byte, 4)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "ok" || time.Since(start) < 400*time.Millisecond {
		t.Fatal(n, err, time.Since(start))
	}
}
