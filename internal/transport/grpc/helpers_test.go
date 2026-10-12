//go:build grpc

package grpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The whole-message reader and decoder the client used before round 14.
// The fake servers in the tests still read client messages with them.

// readMessage reads one gRPC Length-Prefixed-Message and returns its body.
func readMessage(r io.Reader) ([]byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, errors.New("grpc: truncated message header")
		}
		return nil, err
	}
	if h[0] != 0 {
		return nil, errors.New("grpc: compressed messages not supported")
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > maxMessage {
		return nil, fmt.Errorf("grpc: message too large (%d)", n)
	}
	// Grow the buffer as the body arrives instead of allocating n up front
	// (otherwise a server could pin maxMessage bytes per stream by sending
	// only a header), and never past n (a doubling buffer would keep up to
	// 2n alive).
	b := make([]byte, 0, min(int(n), readStep))
	for len(b) < int(n) {
		if len(b) == cap(b) {
			nb := make([]byte, len(b), min(int(n), 2*cap(b)))
			copy(nb, b)
			b = nb
		}
		m, err := io.ReadFull(r, b[len(b):cap(b)])
		b = b[:len(b)+m]
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("grpc: truncated message: %w", err)
		}
	}
	return b, nil
}

// decodeHunks returns the field-1 entries of a Hunk or MultiHunk joined in
// order, skipping unknown fields (protobuf wire format). The entries are
// moved together inside b and the result aliases it: a slice per entry would
// let a server turn one message of 1-byte entries into 8 times its size in
// slice headers.
func decodeHunks(b []byte) ([]byte, error) {
	out := b[:0]
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("grpc: bad protobuf tag")
		}
		b = b[n:]
		switch tag & 7 {
		case 0: // varint
			if _, n = binary.Uvarint(b); n <= 0 {
				return nil, errors.New("grpc: bad protobuf varint")
			}
			b = b[n:]
		case 1: // 64-bit
			if len(b) < 8 {
				return nil, errors.New("grpc: truncated protobuf")
			}
			b = b[8:]
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, errors.New("grpc: truncated protobuf")
			}
			v := b[n : n+int(l)]
			b = b[n+int(l):]
			if tag>>3 == 1 {
				out = append(out, v...) // never ahead of the read position
			}
		case 5: // 32-bit
			if len(b) < 4 {
				return nil, errors.New("grpc: truncated protobuf")
			}
			b = b[4:]
		default:
			return nil, fmt.Errorf("grpc: unsupported protobuf wire type %d", tag&7)
		}
	}
	return out, nil
}
