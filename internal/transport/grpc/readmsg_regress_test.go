//go:build grpc

package grpc

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

func frame(n int) []byte {
	b := make([]byte, 5+n)
	binary.BigEndian.PutUint32(b[1:5], uint32(n))
	return b
}

// A full maxMessage message must end with an exact-size buffer and must not
// allocate much more than the message itself (round-4 fuzzing found a
// doubling buffer keeping 2n alive).
func TestReadMessageExactBuffer(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	msg, err := readMessage(bytes.NewReader(frame(maxMessage)))
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != maxMessage || cap(msg) != maxMessage {
		t.Fatalf("len %d cap %d, want %d", len(msg), cap(msg), maxMessage)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 3*maxMessage {
		t.Fatalf("allocated %d bytes for a %d-byte message", alloc, maxMessage)
	}
	if _, err := readMessage(bytes.NewReader(frame(maxMessage + 1))); err == nil {
		t.Fatal("oversized message accepted")
	}
}
