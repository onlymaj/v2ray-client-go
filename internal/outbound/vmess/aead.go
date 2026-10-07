//go:build vmess

package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"time"
)

// KDF salts, from proxy/vmess/aead/consts.go.
const (
	saltAuthIDKey      = "AES Auth ID Encryption"
	saltRespLenKey     = "AEAD Resp Header Len Key"
	saltRespLenIV      = "AEAD Resp Header Len IV"
	saltRespPayloadKey = "AEAD Resp Header Key"
	saltRespPayloadIV  = "AEAD Resp Header IV"
	saltKDFRoot        = "VMess AEAD KDF"
	saltHeaderKey      = "VMess Header AEAD Key"
	saltHeaderIV       = "VMess Header AEAD Nonce"
	saltHeaderLenKey   = "VMess Header AEAD Key_Length"
	saltHeaderLenIV    = "VMess Header AEAD Nonce_Length"
)

// hashFunc is a one-shot hash over the concatenation of its arguments.
type hashFunc func(parts ...[]byte) []byte

// kdf mirrors proxy/vmess/aead/kdf.go KDF: HMAC-SHA256 keyed with
// "VMess AEAD KDF" is the base hash, and each path element wraps the previous
// hash in another HMAC keyed with that element. The result is that nested
// hash applied to key. Xray builds this by feeding hmac.New a constructor that
// returns the previous hmac; here the nesting is written out explicitly.
func kdf(key []byte, path ...string) []byte {
	h := hashFunc(func(parts ...[]byte) []byte {
		m := hmac.New(sha256.New, []byte(saltKDFRoot))
		for _, p := range parts {
			m.Write(p)
		}
		return m.Sum(nil)
	})
	for _, p := range path {
		h = hmacOver(h, []byte(p))
	}
	return h(key)
}

func kdf16(key []byte, path ...string) []byte { return kdf(key, path...)[:16] }

// hmacOver is RFC 2104 HMAC with h as the underlying hash (block size 64,
// the SHA-256 block size that every level inherits). VMess path elements are
// at most 30 bytes, so the long-key case (which Xray's shared-state
// construction gets subtly different from RFC 2104) never arises.
func hmacOver(h hashFunc, key []byte) hashFunc {
	const blockSize = 64
	if len(key) > blockSize {
		panic("vmess: kdf path element longer than 64 bytes")
	}
	var ipad, opad [blockSize]byte
	copy(ipad[:], key)
	copy(opad[:], key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	return func(parts ...[]byte) []byte {
		inner := h(append([][]byte{ipad[:]}, parts...)...)
		return h(opad[:], inner)
	}
}

func newGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // keys are always 16 bytes
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// createAuthID mirrors proxy/vmess/aead/authid.go CreateAuthID:
// AES-128-ECB(KDF16(cmdKey, "AES Auth ID Encryption"),
// timestamp(8) | random(4) | crc32(first 12 bytes)(4)).
func createAuthID(cmdKey []byte, now int64) [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(now))
	if _, err := rand.Read(b[8:12]); err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(b[12:], crc32.ChecksumIEEE(b[:12]))
	block, err := aes.NewCipher(kdf16(cmdKey, saltAuthIDKey))
	if err != nil {
		panic(err)
	}
	var out [16]byte
	block.Encrypt(out[:], b[:])
	return out
}

// sealHeader mirrors proxy/vmess/aead/encrypt.go SealVMessAEADHeader:
// authID(16) | GCM(len uint16)(18) | nonce(8) | GCM(header)(len+16).
// Both GCM keys/nonces derive from cmdKey with path (authID, nonce), and the
// authID is the additional data.
func sealHeader(cmdKey [16]byte, data []byte) []byte {
	authID := createAuthID(cmdKey[:], time.Now().Unix())
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	aid, n := string(authID[:]), string(nonce[:])

	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(data)))

	out := make([]byte, 0, 16+18+8+len(data)+16)
	out = append(out, authID[:]...)
	out = newGCM(kdf16(cmdKey[:], saltHeaderLenKey, aid, n)).
		Seal(out, kdf(cmdKey[:], saltHeaderLenIV, aid, n)[:12], length[:], authID[:])
	out = append(out, nonce[:]...)
	out = newGCM(kdf16(cmdKey[:], saltHeaderKey, aid, n)).
		Seal(out, kdf(cmdKey[:], saltHeaderIV, aid, n)[:12], data, authID[:])
	return out
}

// readResponseHeader mirrors proxy/vmess/encoding/client.go
// DecodeResponseHeader (AEAD branch): GCM(len)(18) | GCM(payload)(len+16),
// keyed from the response body key/IV with no additional data. It returns
// the decrypted payload: V | option | cmd | cmdLen | cmd data.
func readResponseHeader(r io.Reader, respKey, respIV []byte) ([]byte, error) {
	var encLen [18]byte
	if _, err := io.ReadFull(r, encLen[:]); err != nil {
		return nil, err
	}
	l, err := newGCM(kdf16(respKey, saltRespLenKey)).Open(nil, kdf(respIV, saltRespLenIV)[:12], encLen[:], nil)
	if err != nil {
		return nil, errors.New("vmess: bad response header length (wrong id?)")
	}
	enc := make([]byte, int(binary.BigEndian.Uint16(l))+16)
	if _, err := io.ReadFull(r, enc); err != nil {
		return nil, err
	}
	hdr, err := newGCM(kdf16(respKey, saltRespPayloadKey)).Open(nil, kdf(respIV, saltRespPayloadIV)[:12], enc, nil)
	if err != nil {
		return nil, errors.New("vmess: bad response header")
	}
	if len(hdr) < 4 {
		return nil, errors.New("vmess: short response header")
	}
	return hdr, nil
}
