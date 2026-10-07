//go:build reality

package reality

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

func fixedKey(t *testing.T, b byte) *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fakeHello is a ClientHello-shaped buffer: type, len[3], version[2],
// random[32] at 6, session id len 32 at 38, session id at 39, then junk.
func fakeHello() (raw, random []byte) {
	raw = make([]byte, 120)
	raw[0] = 1
	for i := range 32 {
		raw[6+i] = byte(i + 1)
		raw[39+i] = 0xee // utls' random session id, must be replaced
	}
	raw[38] = 32
	for i := 71; i < len(raw); i++ {
		raw[i] = byte(i)
	}
	return raw, raw[6:38]
}

// TestSealSessionID seals with the client key and opens the result the way
// the REALITY server does (xtls/reality tls.go: ECDH with its private key,
// same HKDF, AES-GCM open with the session id zeroed in the AAD).
func TestSealSessionID(t *testing.T) {
	client, server := fixedKey(t, 1), fixedKey(t, 2)
	shared, _ := client.ECDH(server.PublicKey())
	raw, random := fakeHello()
	sid := make([]byte, 32)
	shortID := [8]byte{0xab, 0xcd}
	authKey, err := sealSessionID(raw, random, sid, shared, 0x01020304, shortID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw[39:71], sid) {
		t.Fatal("raw does not carry the sealed session id")
	}
	// Server side.
	sshared, _ := server.ECDH(client.PublicKey())
	key := make([]byte, 32)
	hkdf.New(sha256.New, sshared, random[:20], []byte("REALITY")).Read(key)
	if !bytes.Equal(key, authKey) {
		t.Fatal("auth key mismatch")
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	aad := append([]byte(nil), raw...)
	clear(aad[39:71])
	plain, err := aead.Open(nil, random[20:], sid, aad)
	if err != nil {
		t.Fatal("server cannot open session id:", err)
	}
	want := []byte{26, 3, 27, 0, 1, 2, 3, 4, 0xab, 0xcd, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(plain, want) {
		t.Fatalf("plain %x want %x", plain, want)
	}
	if got := hex.EncodeToString(sid); got != sealedVector {
		t.Fatalf("sealed sid %s, want %s", got, sealedVector)
	}
}

// sealedVector pins the output for the fixed inputs above (regression).
const sealedVector = "8d4428d396aca5d83d0eaaf09b66138e86a754ecfb15e14a5a44caa90dfe33f6"

// realityCert builds a certificate the way the REALITY server does: an
// ed25519 cert whose signature is replaced by HMAC-SHA512(authKey, pubkey).
func realityCert(t *testing.T, authKey []byte) []byte {
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	copy(der[len(der)-64:], h.Sum(nil)) // signature BIT STRING is last
	return der
}

func TestVerifyCert(t *testing.T) {
	authKey := bytes.Repeat([]byte{9}, 32)
	der := realityCert(t, authKey)
	ok, err := verifyCert([][]byte{der}, authKey, "example.com")
	if !ok || err != nil {
		t.Fatalf("valid reality cert rejected: %v %v", ok, err)
	}
	ok, err = verifyCert([][]byte{der}, bytes.Repeat([]byte{8}, 32), "example.com")
	if ok || err == nil {
		t.Fatal("cert with wrong HMAC accepted")
	}
}

func TestX25519Key(t *testing.T) {
	x := fixedKey(t, 3)
	p, _ := ecdh.P256().GenerateKey(rand.Reader)
	if x25519Key(&utls.KeySharePrivateKeys{Ecdhe: x}) != x {
		t.Error("plain X25519")
	}
	if x25519Key(&utls.KeySharePrivateKeys{Ecdhe: p, MlkemEcdhe: x}) != x {
		t.Error("hybrid fallback when first share is P-256")
	}
	if x25519Key(&utls.KeySharePrivateKeys{Ecdhe: p}) != nil {
		t.Error("P-256 only must fail")
	}
}

// TestBuildHello checks the real uTLS fingerprints give us an X25519 key
// whose public half is in the ClientHello and a 32-byte session id at 39.
func TestBuildHello(t *testing.T) {
	for _, fp := range []string{"chrome", "firefox", "safari"} {
		l, err := New([]byte(`{"fingerprint":"` + fp + `","publicKey":"` +
			"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA" + `","shortId":"abcd"}`))
		if err != nil {
			t.Fatal(err)
		}
		u := utls.UClient(nil, &utls.Config{ServerName: "example.com"}, l.(*layer).id)
		if err := u.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		k := x25519Key(u.HandshakeState.State13.KeyShareKeys)
		if k == nil {
			t.Fatalf("%s: no X25519 key", fp)
		}
		raw := u.HandshakeState.Hello.Raw
		if raw[38] != 32 {
			t.Fatalf("%s: session id len %d", fp, raw[38])
		}
		if !bytes.Contains(raw, k.PublicKey().Bytes()) {
			t.Fatalf("%s: X25519 public key not in hello", fp)
		}
	}
}
