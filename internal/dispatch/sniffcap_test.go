package dispatch

import (
	"net"
	"testing"
	"time"
)

// Round 22: peek parsed the whole head again after every read, so a device
// sending an HTTP-looking head one byte per packet cost a parse of up to
// 4 KiB for each byte. It gives up after maxSniffReads reads and the
// connection goes on unsniffed.
func TestPeekGivesUpOnATrickledHead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	head := "GET / HTTP/1.1\r\n" + "X-A: bcdefghijklmnopqrstuvwxyz\r\n"
	wrote := make(chan int, 1)
	go func() {
		n := 0
		for i := range head {
			b.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := b.Write([]byte{head[i]}); err != nil {
				break
			}
			n++
		}
		wrote <- n
	}()
	got, domain, err := peek(a, make([]byte, sniffMax))
	if err != nil || domain != "" || len(got) != maxSniffReads {
		t.Fatalf("peek returned %d bytes, domain %q, err %v; want %d bytes after as many reads", len(got), domain, err, maxSniffReads)
	}
	if n := <-wrote; n > maxSniffReads+1 {
		t.Fatalf("%d bytes were taken from the device, want %d", n, maxSniffReads)
	}
}
