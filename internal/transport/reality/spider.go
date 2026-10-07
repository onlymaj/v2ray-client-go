//go:build reality

package reality

import (
	"bytes"
	"encoding/binary"
	"io"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

// spider is a minimal stand-in for the crawler in Xray's UClient: when the
// handshake reached the real camouflage site, fetch spiderX once like a
// browser would, then close. Xray's version keeps crawling links with
// random concurrency (SpiderY); a single GET keeps the binary small. HTTP/2
// is spoken by hand with hpack so net/http is not linked in.
func spider(c *utls.UConn, host, path string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if c.ConnectionState().NegotiatedProtocol == "h2" {
		spiderH2(c, host, path)
		return
	}
	io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: "+userAgent+
		"\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
		"Accept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n")
	io.Copy(io.Discard, io.LimitReader(c, 1<<20))
}

// HTTP/2 frame types and flags (RFC 9113 section 6).
const (
	frameData     = 0x0
	frameHeaders  = 0x1
	frameSettings = 0x4
	frameGoAway   = 0x7
	flagAck       = 0x1
	flagEndStream = 0x1
	flagEndHdrs   = 0x4
)

func writeFrame(w io.Writer, typ, flags byte, stream uint32, payload []byte) error {
	var h [9]byte
	h[0], h[1], h[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	h[3], h[4] = typ, flags
	binary.BigEndian.PutUint32(h[5:], stream)
	_, err := w.Write(append(h[:], payload...))
	return err
}

func spiderH2(c io.ReadWriter, host, path string) {
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{
		{":method", "GET"}, {":authority", host}, {":scheme", "https"}, {":path", path},
		{"user-agent", userAgent},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"accept-language", "en-US,en;q=0.9"},
	} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if _, err := io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		return
	}
	if writeFrame(c, frameSettings, 0, 0, nil) != nil ||
		writeFrame(c, frameHeaders, flagEndStream|flagEndHdrs, 1, hb.Bytes()) != nil {
		return
	}
	var h [9]byte
	for read := 0; read < 1<<20; {
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return
		}
		n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
			return
		}
		read += n
		stream := binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
		switch h[3] {
		case frameSettings:
			if h[4]&flagAck == 0 && writeFrame(c, frameSettings, flagAck, 0, nil) != nil {
				return
			}
		case frameData, frameHeaders:
			if stream == 1 && h[4]&flagEndStream != 0 {
				return
			}
		case frameGoAway:
			return
		}
	}
}
