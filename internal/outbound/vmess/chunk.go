//go:build vmess

package vmess

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Security byte values, from common/protocol/headers.pb.go SecurityType.
const (
	secAES128GCM = 3
	secChaCha20  = 4
	secNone      = 5
	secZero      = 6 // never on the wire: sent as secNone with no chunk options
)

// Request option bits, from common/protocol/headers.go.
const (
	optChunkStream   = 0x01
	optChunkMasking  = 0x04
	optGlobalPadding = 0x08
)

// bufSize is Xray's buf.Size; chunk payloads are sized to fit one buffer.
const bufSize = 8192

// chunkCodec frames one direction of the body. It mirrors the pieces Xray
// assembles in proxy/vmess/encoding/client.go EncodeRequestBody /
// DecodeResponseBody:
//   - aead != nil: common/crypto/auth.go AuthenticationWriter/Reader
//     (size | AEAD(payload) | padding);
//   - aead == nil: common/crypto/chunk.go ChunkStreamWriter/Reader
//     (size | payload), used by security "none".
//
// The 2-byte size is XORed with SHAKE128(iv) output when masking is on
// (encoding/auth.go ShakeSizeParser); with padding on, the same SHAKE stream
// also yields the padding length, drawn before the size mask.
type chunkCodec struct {
	aead    cipher.AEAD
	nonce   []byte      // IV copy; first 2 bytes replaced by the chunk counter
	count   int         // chunks sealed or opened; at most maxChunks unless wrap
	wrap    bool        // let the counter wrap like Xray (see Settings.AllowNonceWrap)
	shake   *sha3.SHAKE // nil: plain sizes
	padding bool
}

func newChunkCodec(security byte, key, iv []byte, opt byte) *chunkCodec {
	c := &chunkCodec{nonce: append([]byte(nil), iv...)}
	switch security {
	case secAES128GCM:
		c.aead = newGCM(key)
	case secChaCha20:
		var err error
		c.aead, err = chacha20poly1305.New(chachaKey(key))
		if err != nil {
			panic(err)
		}
	}
	if opt&optChunkMasking != 0 {
		c.shake = sha3.NewSHAKE128()
		c.shake.Write(iv)
	}
	c.padding = opt&optGlobalPadding != 0 && c.shake != nil
	return c
}

// chachaKey mirrors encoding/auth.go GenerateChacha20Poly1305Key:
// md5(k) | md5(md5(k)).
func chachaKey(k []byte) []byte {
	a := md5.Sum(k)
	b := md5.Sum(a[:])
	return append(a[:], b[:]...)
}

// maxChunks is the number of distinct 16-bit chunk counters. Xray's
// GenerateChunkNonce wraps after that and reuses nonces under the same key
// (about 512 MiB into a stream); we fail the stream instead, unless wrap is
// set because an outer TLS/REALITY layer protects the stream.
const maxChunks = 1 << 16

var errNonceExhausted = errors.New("vmess: chunk nonce space exhausted")

// nextNonce mirrors encoding/client.go GenerateChunkNonce; it wraps only
// when c.wrap is set.
func (c *chunkCodec) nextNonce() ([]byte, error) {
	if c.count >= maxChunks && !c.wrap {
		return nil, errNonceExhausted
	}
	binary.BigEndian.PutUint16(c.nonce, uint16(c.count))
	c.count++
	return c.nonce[:c.aead.NonceSize()], nil
}

func (c *chunkCodec) mask() uint16 {
	if c.shake == nil {
		return 0
	}
	var b [2]byte
	c.shake.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// nextPadding mirrors ShakeSizeParser.NextPaddingLen.
func (c *chunkCodec) nextPadding() int {
	if !c.padding {
		return 0
	}
	return int(c.mask() % 64)
}

func (c *chunkCodec) overhead() int {
	if c.aead == nil {
		return 0
	}
	return c.aead.Overhead()
}

// maxPayload mirrors the per-chunk split in AuthenticationWriter.writeStream
// and ChunkStreamWriter.WriteMultiBuffer.
func (c *chunkCodec) maxPayload() int {
	if c.aead == nil {
		return bufSize
	}
	n := bufSize - c.overhead() - 2
	if c.padding {
		n -= 64
	}
	return n
}

// seal appends one chunk carrying p (len(p) <= maxPayload) to dst. An empty p
// is the end-of-stream marker (Xray writes an empty MultiBuffer on EOF).
func (c *chunkCodec) seal(dst, p []byte) ([]byte, error) {
	if c.aead == nil {
		dst = binary.BigEndian.AppendUint16(dst, uint16(len(p))^c.mask())
		return append(dst, p...), nil
	}
	nonce, err := c.nextNonce()
	if err != nil {
		return dst, err
	}
	// AuthenticationWriter.seal: padding length first, then the size mask.
	pad := c.nextPadding()
	size := len(p) + c.overhead() + pad
	dst = binary.BigEndian.AppendUint16(dst, uint16(size)^c.mask())
	dst = c.aead.Seal(dst, nonce, p, nil)
	if pad > 0 {
		start := len(dst)
		dst = append(dst, make([]byte, pad)...)
		rand.Read(dst[start:])
	}
	return dst, nil
}

// maxChunkIn bounds the payload of a received chunk. The size field allows
// 64 KiB and is only masked, not authenticated, and the buffer is allocated
// before the body arrives: a server (or, without TLS, anyone on the path)
// could make every connection hold 64 KiB for two bytes. The VMess spec
// caps a chunk at 2^14 and Xray never sends more than 8 KiB.
const maxChunkIn = 1 << 14

var errChunkTooLarge = errors.New("vmess: chunk too large")

// open reads one chunk from r and returns its plaintext; io.EOF marks the
// end-of-stream chunk. buf is reused when large enough.
func (c *chunkCodec) open(r io.Reader, buf []byte) ([]byte, error) {
	var sb [2]byte
	if _, err := io.ReadFull(r, sb[:]); err != nil {
		return nil, err
	}
	if c.aead == nil { // ChunkStreamReader: no padding, size 0 ends
		size := int(binary.BigEndian.Uint16(sb[:]) ^ c.mask())
		if size == 0 {
			return nil, io.EOF
		}
		if size > maxChunkIn {
			return nil, errChunkTooLarge
		}
		if cap(buf) < size {
			buf = make([]byte, size)
		}
		_, err := io.ReadFull(r, buf[:size])
		return buf[:size], err
	}
	// AuthenticationReader.readSize: padding length first, then the size.
	pad := c.nextPadding()
	size := int(binary.BigEndian.Uint16(sb[:]) ^ c.mask())
	if size == c.overhead()+pad {
		return nil, io.EOF
	} else if size < c.overhead()+pad {
		return nil, errors.New("vmess: invalid chunk size")
	}
	if size > maxChunkIn+c.overhead()+pad {
		return nil, errChunkTooLarge
	}
	if cap(buf) < size {
		buf = make([]byte, size)
	}
	buf = buf[:size]
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	nonce, err := c.nextNonce()
	if err != nil {
		return nil, err
	}
	pt, err := c.aead.Open(buf[:0], nonce, buf[:size-pad], nil)
	if err != nil {
		return nil, errors.New("vmess: chunk authentication failed")
	}
	return pt, nil
}
