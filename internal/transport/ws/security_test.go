//go:build ws

package ws

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Settings that would inject into the handshake request are rejected.
func TestNewRejectsInvalidSettings(t *testing.T) {
	for _, s := range []string{
		`{"path":"/ HTTP/1.1\r\nX-Inj: 1\r\n\r\nGET /smuggled"}`,
		`{"path":"/a b"}`,
		`{"path":"/a\u0000"}`,
		`{"host":"h\r\nEvil: yes"}`,
		`{"host":"a b"}`,
		`{"headers":{"X\r\nY":"v"}}`,
		`{"headers":{"X":"v\r\nY: z"}}`,
		`{"headers":{"Host":"h\r\nEvil: yes"}}`,
	} {
		if _, err := New([]byte(s)); err == nil {
			t.Errorf("%s: accepted", s)
		}
	}
	if _, err := New([]byte(`{"path":"ray?ed=2048","host":"ws.example.com:8443","headers":{"X-A":"b c"}}`)); err != nil {
		t.Fatal(err)
	}
}

// A server streaming an endless response header must be cut off at
// maxHandshake instead of growing memory.
func TestHandshakeHeaderLimit(t *testing.T) {
	l, err := New([]byte(`{"path":"/"}`))
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		br := bufio.NewReader(b)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		b.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nX: "))
		chunk := []byte(strings.Repeat("a", 64<<10))
		for i := 0; i < 64; i++ { // 4 MiB
			if _, err := b.Write(chunk); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := l.Wrap(ctx, a); !errors.Is(err, errHandshakeTooLarge) {
		t.Fatalf("err = %v, want %v", err, errHandshakeTooLarge)
	}
}
