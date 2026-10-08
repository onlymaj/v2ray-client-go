//go:build vmess

package vmess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// Expected values produced by running Xray's proxy/vmess/aead/kdf.go KDF.
func TestKDFVectors(t *testing.T) {
	key := []byte("Demo Key for Auth ID Test")
	for _, tc := range []struct {
		key  []byte
		path []string
		want string
	}{
		{key, nil, "7b9d2c2e1fab0b407a2ec00bab371b9667ca35f6674086ef384251821f6005f8"},
		{key, []string{"Demo Path for Auth ID Test"}, "66e41ad47fa745fbfd1e97325e93dbf4a04daac03e50fdf3052da7136662dfe1"},
		{key, []string{"Demo Path for Auth ID Test", "second", "third"}, "32ff1c87799bb57f90db235854c4232647e22d4b4071867ce6c224b6a975144b"},
		{[]byte("0123456789abcdef"), []string{saltHeaderLenIV, "AAAAAAAAAAAAAAAA", "nonce-8b"}, "00d6d02ca0eb79ccaa6261e5ba3aef23dea130270ad2dcdf64d2165285f53389"},
	} {
		if got := hex.EncodeToString(kdf(tc.key, tc.path...)); got != tc.want {
			t.Errorf("kdf(%q, %q) = %s, want %s", tc.key, tc.path, got, tc.want)
		}
	}
}

// decodeAuthID is the server half of aead/authid.go (AuthIDDecoder.Decode).
func decodeAuthID(cmdKey []byte, id [16]byte) (int64, bool) {
	b, _ := aes.NewCipher(kdf16(cmdKey, saltAuthIDKey))
	b.Decrypt(id[:], id[:])
	return int64(binary.BigEndian.Uint64(id[:8])), binary.BigEndian.Uint32(id[12:]) == crc32.ChecksumIEEE(id[:12])
}

func TestAuthIDRoundTrip(t *testing.T) {
	key := kdf16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	now := time.Now().Unix()
	ts, ok := decodeAuthID(key, createAuthID(key, now))
	if !ok || ts != now {
		t.Fatalf("decode = %d, %v; want %d, true", ts, ok, now)
	}
	other := kdf16([]byte("other"))
	if _, ok := decodeAuthID(other, createAuthID(key, now)); ok {
		t.Fatal("authID matched under the wrong key")
	}
}

// openHeader is the server half of aead/encrypt.go (OpenVMessAEADHeader).
func openHeader(cmdKey [16]byte, r io.Reader) ([]byte, error) {
	var authID [16]byte
	var encLen [18]byte
	var nonce [8]byte
	for _, b := range [][]byte{authID[:], encLen[:], nonce[:]} {
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
	}
	if _, ok := decodeAuthID(cmdKey[:], authID); !ok {
		return nil, errors.New("bad authID")
	}
	aid, n := string(authID[:]), string(nonce[:])
	l, err := newGCM(kdf16(cmdKey[:], saltHeaderLenKey, aid, n)).Open(nil, kdf(cmdKey[:], saltHeaderLenIV, aid, n)[:12], encLen[:], authID[:])
	if err != nil {
		return nil, err
	}
	enc := make([]byte, int(binary.BigEndian.Uint16(l))+16)
	if _, err := io.ReadFull(r, enc); err != nil {
		return nil, err
	}
	return newGCM(kdf16(cmdKey[:], saltHeaderKey, aid, n)).Open(nil, kdf(cmdKey[:], saltHeaderIV, aid, n)[:12], enc, authID[:])
}

// sealResponseHeader is the server half of encoding/server.go
// EncodeResponseHeader (AEAD branch).
func sealResponseHeader(respKey, respIV []byte, hdr []byte) []byte {
	l := binary.BigEndian.AppendUint16(nil, uint16(len(hdr)))
	out := newGCM(kdf16(respKey, saltRespLenKey)).Seal(nil, kdf(respIV, saltRespLenIV)[:12], l, nil)
	return newGCM(kdf16(respKey, saltRespPayloadKey)).Seal(out, kdf(respIV, saltRespPayloadIV)[:12], hdr, nil)
}

func TestHeaderSealOpen(t *testing.T) {
	var key [16]byte
	rand.Read(key[:])
	want := []byte("Test Header")
	sealed := sealHeader(key, want)
	got, err := openHeader(key, bytes.NewReader(sealed))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("open = %q, %v", got, err)
	}
	for i := range sealed { // any flipped byte must be rejected
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0xff
		if _, err := openHeader(key, bytes.NewReader(bad)); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}

	rk, ri := make([]byte, 16), make([]byte, 16)
	rand.Read(rk)
	rand.Read(ri)
	resp := []byte{0x42, 0, 0, 0}
	got, err = readResponseHeader(bytes.NewReader(sealResponseHeader(rk, ri, resp)), rk, ri)
	if err != nil || !bytes.Equal(got, resp) {
		t.Fatalf("response header = %x, %v", got, err)
	}
}

var securities = map[string]byte{"aes-128-gcm": secAES128GCM, "chacha20-poly1305": secChaCha20, "none": secNone}

func TestChunkRoundTrip(t *testing.T) {
	for name, sec := range securities {
		for _, opt := range []byte{optChunkStream, optChunkStream | optChunkMasking, optChunkStream | optChunkMasking | optGlobalPadding} {
			key, iv := make([]byte, 16), make([]byte, 16)
			rand.Read(key)
			rand.Read(iv)
			enc, dec := newChunkCodec(sec, key, iv, opt), newChunkCodec(sec, key, iv, opt)
			var wire []byte
			var msgs [][]byte
			for _, n := range []int{1, 100, enc.maxPayload(), 0} {
				m := make([]byte, n)
				rand.Read(m)
				msgs = append(msgs, m)
				var err error
				if wire, err = enc.seal(wire, m); err != nil {
					t.Fatal(err)
				}
			}
			r := bytes.NewReader(wire)
			for i, m := range msgs[:len(msgs)-1] {
				got, err := dec.open(r, nil)
				if err != nil || !bytes.Equal(got, m) {
					t.Fatalf("%s opt=%x chunk %d: len %d err %v", name, opt, i, len(got), err)
				}
			}
			if _, err := dec.open(r, nil); err != io.EOF {
				t.Fatalf("%s opt=%x: end marker gave %v", name, opt, err)
			}
			// Like Xray's AuthenticationReader, the end marker's tag and
			// padding are left unread.
			if want := enc.overhead(); r.Len() < want {
				t.Fatalf("%s opt=%x: %d trailing bytes, want >= %d", name, opt, r.Len(), want)
			}
		}
	}
}

// The 16-bit chunk counter must not wrap: sealing or opening the 65537th
// chunk under one key fails instead of reusing nonce 0.
func TestChunkNonceExhausted(t *testing.T) {
	for name, sec := range securities {
		key, iv := make([]byte, 16), make([]byte, 16)
		opt := byte(optChunkStream | optChunkMasking)
		enc, dec := newChunkCodec(sec, key, iv, opt), newChunkCodec(sec, key, iv, opt)
		if enc.aead == nil {
			continue // security none: no nonces
		}
		enc.count, dec.count = maxChunks-1, maxChunks-1
		wire, err := enc.seal(nil, []byte("last"))
		if err != nil {
			t.Fatalf("%s: last chunk: %v", name, err)
		}
		if _, err := enc.seal(wire, []byte("wrap")); err != errNonceExhausted {
			t.Fatalf("%s: seal past the counter gave %v", name, err)
		}
		r := bytes.NewReader(wire)
		if got, err := dec.open(r, nil); err != nil || string(got) != "last" {
			t.Fatalf("%s: open last chunk: %q %v", name, got, err)
		}
		// A server that keeps going: same key, counter would wrap to 0.
		srv := newChunkCodec(sec, key, iv, opt)
		srv.shake, dec.shake = nil, nil // plain sizes so the stream can be resynced
		more, _ := srv.seal(nil, []byte("wrap"))
		if _, err := dec.open(bytes.NewReader(more), nil); err != errNonceExhausted {
			t.Fatalf("%s: open past the counter gave %v", name, err)
		}
	}
}

// fakeServer decodes one VMess request like encoding/server.go would,
// checks it, then echoes the body back in the response stream.
func fakeServer(t *testing.T, conn net.Conn, cmdKey [16]byte, wantSec, wantOpt byte, wantAddr []byte) error {
	defer conn.Close()
	br := bufio.NewReader(conn)
	h, err := openHeader(cmdKey, br)
	if err != nil {
		return err
	}
	f := fnv.New32a()
	f.Write(h[:len(h)-4])
	if !bytes.Equal(f.Sum(nil), h[len(h)-4:]) {
		return errors.New("fnv mismatch")
	}
	if h[0] != 1 {
		return errors.New("bad version")
	}
	iv, key, v, opt := h[1:17], h[17:33], h[33], h[34]
	padLen, sec := int(h[35]>>4), h[35]&0x0f
	if sec != wantSec || opt != wantOpt || h[36] != 0 || h[37] != 1 {
		return errors.New("bad security/option/command")
	}
	if addr := h[38 : len(h)-4-padLen]; !bytes.Equal(addr, wantAddr) {
		return errors.New("bad address " + hex.EncodeToString(addr))
	}

	rk, ri := sha256.Sum256(key), sha256.Sum256(iv)
	respKey, respIV := rk[:16], ri[:16]
	out := sealResponseHeader(respKey, respIV, []byte{v, 0, 0, 0})

	if opt&optChunkStream == 0 { // zero: raw echo of the first 5 bytes
		b := make([]byte, 5)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		_, err := conn.Write(append(out, b...))
		return err
	}
	dec, enc := newChunkCodec(sec, key, iv, opt), newChunkCodec(sec, respKey, respIV, opt)
	for {
		p, err := dec.open(br, nil)
		if err == io.EOF {
			if out, err = enc.seal(out, nil); err != nil {
				return err
			}
			_, err = conn.Write(out)
			return err
		}
		if err != nil {
			return err
		}
		if out, err = enc.seal(out, p); err != nil {
			return err
		}
		if _, err := conn.Write(out); err != nil {
			return err
		}
		out = out[:0]
	}
}

func TestClientAgainstFakeServer(t *testing.T) {
	const id = "b831381d-6324-4d53-ad4f-8cda48b30811"
	u, _ := parseUUID(id)
	for _, tc := range []struct {
		security string
		sec, opt byte
	}{
		{"aes-128-gcm", secAES128GCM, 0x0d},
		{"chacha20-poly1305", secChaCha20, 0x0d},
		{"none", secNone, 0x05},
		{"zero", secNone, 0x00},
	} {
		t.Run(tc.security, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			settings, _ := json.Marshal(Settings{ID: id, Security: tc.security})
			d, err := newDialer(settings, func(context.Context) (net.Conn, error) { return client, nil })
			if err != nil {
				t.Fatal(err)
			}
			dest := outbound.Addr{IP: netip.MustParseAddr("1.2.3.4"), Port: 443}
			cmdKey := d.(*dialer).cmdKey
			if want := md5Of(u); cmdKey != want {
				t.Fatal("cmdKey mismatch")
			}
			done := make(chan error, 1)
			go func() { done <- fakeServer(t, server, cmdKey, tc.sec, tc.opt, []byte{1, 0xbb, 1, 1, 2, 3, 4}) }()

			c, err := d.Dial(context.Background(), "tcp", dest)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("hello")
			if tc.security != "zero" {
				msg = make([]byte, 50000) // several chunks
				rand.Read(msg)
			}
			go func() {
				c.Write(msg)
				c.(interface{ CloseWrite() error }).CloseWrite()
			}()
			got, err := io.ReadAll(c)
			if tc.security == "zero" && errors.Is(err, io.ErrClosedPipe) {
				err = nil
			}
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("echo: got %d bytes, err %v", len(got), err)
			}
			if err := <-done; err != nil {
				t.Fatal("server:", err)
			}
		})
	}
}

// md5Of is common/protocol/id.go NewID's cmdKey.
func md5Of(u [16]byte) [16]byte {
	return md5.Sum(append(u[:], "c48619fe-8f02-49e0-b9e9-edf763e17e21"...))
}

func TestAppendAddr(t *testing.T) {
	for _, tc := range []struct {
		a    outbound.Addr
		want string
	}{
		{outbound.Addr{Domain: "example.com", Port: 80}, "0050020b6578616d706c652e636f6d"},
		{outbound.Addr{IP: netip.MustParseAddr("::ffff:10.0.0.1"), Port: 53}, "0035010a000001"},
		{outbound.Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 1}, "00010320010db8000000000000000000000001"},
	} {
		b, err := appendAddr(nil, tc.a)
		if err != nil || hex.EncodeToString(b) != tc.want {
			t.Errorf("%v: %x %v, want %s", tc.a, b, err, tc.want)
		}
	}
}

func TestSettings(t *testing.T) {
	nop := func(context.Context) (net.Conn, error) { return nil, nil }
	if _, err := newDialer([]byte(`{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":64}`), nop); err == nil {
		t.Error("alterId 64 accepted")
	}
	if _, err := newDialer([]byte(`{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"rc4"}`), nop); err == nil {
		t.Error("bad security accepted")
	}
	if _, err := newDialer([]byte(`{"id":"short-name"}`), nop); err != nil {
		t.Error("short id (UUIDv5 mapping) rejected:", err)
	}
}
