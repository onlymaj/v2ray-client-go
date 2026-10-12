//go:build reality

// Package reality is the "reality" transport layer: a uTLS client that
// authenticates itself to an Xray REALITY server inside the ClientHello
// session ID. Mirrors UClient in Xray's transport/internet/reality/reality.go.
package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"

	"github.com/onlymaj/v2ray-client-go/internal/transport"
	ntls "github.com/onlymaj/v2ray-client-go/internal/transport/tls"
)

// version is written into session ID bytes 0..2 (Xray writes core.Version_x/
// y/z). Servers only check it when minClientVer/maxClientVer are set; this is
// the Xray version the code was written against (v26.3.27).
var version = [3]byte{26, 3, 27}

type Settings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"` // server x25519 key, base64 raw URL
	ShortID     string `json:"shortId"`   // hex, up to 8 bytes
	SpiderX     string `json:"spiderX"`   // fallback crawl path, default "/"
}

type layer struct {
	s         Settings
	id        utls.ClientHelloID
	publicKey *ecdh.PublicKey
	shortID   [8]byte
}

// roots verifies a real (non-Reality) certificate; nil means the system
// roots. Tests set it.
var roots *x509.CertPool

// spiders limits concurrent spider fetches.
var spiders = make(chan struct{}, 2)

func init() {
	transport.Register("reality", New)
}

func New(settings []byte) (transport.Layer, error) {
	l := &layer{}
	if err := json.Unmarshal(settings, &l.s); err != nil {
		return nil, err
	}
	var err error
	if l.id, err = ntls.Fingerprint(l.s.Fingerprint); err != nil {
		return nil, err
	}
	pk, err := base64.RawURLEncoding.DecodeString(l.s.PublicKey)
	if err != nil {
		return nil, errors.New("reality: bad publicKey")
	}
	if l.publicKey, err = ecdh.X25519().NewPublicKey(pk); err != nil {
		return nil, errors.New("reality: bad publicKey")
	}
	sid, err := hex.DecodeString(l.s.ShortID)
	if err != nil || len(sid) > 8 {
		return nil, errors.New("reality: bad shortId")
	}
	copy(l.shortID[:], sid) // shorter IDs are zero padded, as in Xray
	if l.s.SpiderX == "" || l.s.SpiderX[0] != '/' {
		l.s.SpiderX = "/" + l.s.SpiderX
	}
	return l, nil
}

func (l *layer) Wrap(ctx context.Context, conn net.Conn) (net.Conn, error) {
	sni := ntls.ServerNameOr(l.s.ServerName, conn)
	var authKey []byte
	verified := false
	rec := ntls.NewRecordConn(conn)
	u := utls.UClient(rec, &utls.Config{
		ServerName: sni,
		// Verification happens in VerifyPeerCertificate below.
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			ok, err := verifyCert(rawCerts, authKey, sni)
			verified = ok
			return err
		},
	}, l.id)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	priv := x25519Key(u.HandshakeState.State13.KeyShareKeys)
	if priv == nil {
		return nil, errors.New("reality: fingerprint has no X25519 key share (needs TLS 1.3)")
	}
	shared, err := priv.ECDH(l.publicKey)
	if err != nil {
		return nil, err
	}
	hello := u.HandshakeState.Hello
	if len(hello.Raw) < 39+32 || hello.Raw[38] != 32 {
		return nil, errors.New("reality: fingerprint does not send a 32-byte session ID")
	}
	hello.SessionId = make([]byte, 32)
	authKey, err = sealSessionID(hello.Raw, hello.Random, hello.SessionId, shared,
		uint32(time.Now().Unix()), l.shortID)
	if err != nil {
		return nil, err
	}
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verified {
		// A real certificate: we reached the camouflage site, not an Xray
		// server (MITM or redirection). Behave like a browser, then fail.
		// At most two at a time: every failed dial would otherwise start
		// one, each holding a connection for up to 10 s.
		err := errors.New("reality: received real certificate (potential MITM or redirection)")
		select {
		case spiders <- struct{}{}:
			go func() {
				defer func() { <-spiders }()
				spider(u, sni, l.s.SpiderX)
			}()
			// The caller would close conn under the spider before it sent
			// its request, leaving a handshake followed by an instant
			// close: the pattern the spider exists to avoid.
			return nil, fmt.Errorf("%w (%w)", err, transport.ErrConnKept)
		default:
			u.Close()
		}
		return nil, err
	}
	return ntls.NewConn(u, rec), nil
}

// x25519Key returns the X25519 private key whose public half is in the
// ClientHello key_share. uTLS v1.8.2 (u_parrots.go, KeyShareExtension case)
// stores the first plain ECDHE share in Ecdhe and the X25519 half of an
// X25519MLKEM768 hybrid share in MlkemEcdhe. Chrome sends both, sharing no
// key, so either works for the server; prefer the plain X25519 share like
// Xray does, but only if it really is X25519 (Firefox lists other curves).
func x25519Key(k *utls.KeySharePrivateKeys) *ecdh.PrivateKey {
	if k == nil {
		return nil
	}
	if k.Ecdhe != nil && k.Ecdhe.Curve() == ecdh.X25519() {
		return k.Ecdhe
	}
	if k.MlkemEcdhe != nil && k.MlkemEcdhe.Curve() == ecdh.X25519() {
		return k.MlkemEcdhe
	}
	return nil
}

// sealSessionID builds the REALITY session ID and seals it into sid (32
// bytes) and raw (the marshalled ClientHello, session ID at offset 39).
// Layout before sealing: version[3] | 0 | unix time BE[4] | shortId[8].
// authKey = HKDF-SHA256(ECDH, salt=random[:20], info="REALITY");
// sid = AES-GCM(authKey).Seal(nonce=random[20:], plain=sid[:16],
// aad=raw with an all-zero session ID).
func sealSessionID(raw, random, sid, shared []byte, now uint32, shortID [8]byte) ([]byte, error) {
	clear(sid)
	copy(raw[39:39+32], sid)
	copy(sid, version[:])
	sid[3] = 0
	binary.BigEndian.PutUint32(sid[4:], now)
	copy(sid[8:], shortID[:])

	authKey := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, shared, random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(sid[:0], random[20:], sid[:16], raw)
	copy(raw[39:], sid)
	return authKey, nil
}

// verifyCert mirrors UConn.VerifyPeerCertificate: a REALITY server presents
// an ed25519 certificate whose signature field is HMAC-SHA512(authKey,
// pubkey). Anything else must be a valid WebPKI chain for sni (then the
// handshake succeeds but verified is false). ML-DSA-65 extra verification
// (mldsa65Verify) is not supported.
func verifyCert(rawCerts [][]byte, authKey []byte, sni string) (bool, error) {
	if len(rawCerts) == 0 {
		return false, errors.New("reality: no certificate")
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return false, err
		}
		certs[i] = c
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			return true, nil
		}
	}
	opts := x509.VerifyOptions{DNSName: sni, Intermediates: x509.NewCertPool(), Roots: roots}
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(opts)
	return false, err
}
