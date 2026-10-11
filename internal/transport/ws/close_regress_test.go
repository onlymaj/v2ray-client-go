//go:build ws

package ws

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// Regression (round 7): Close must not wait for a Write stuck on a peer that
// never reads; relays are closed from config updates, and a hang there
// stopped every later config change from being applied.
func TestCloseDoesNotWaitForStuckWrite(t *testing.T) {
	a, b := net.Pipe() // b never reads, so a Write on a blocks
	defer b.Close()
	c := &Conn{Conn: a, br: bufio.NewReader(a)}
	go c.Write(make([]byte, 64<<10))
	time.Sleep(50 * time.Millisecond) // let the Write take the frame lock
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind a stuck Write")
	}
}
