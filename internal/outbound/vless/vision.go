//go:build vless

package vless

// XTLS Vision (flow "xtls-rprx-vision"), client side. Mirrors proxy/proxy.go
// in Xray: TrafficState, VisionReader, VisionWriter, IsCompleteRecord,
// ReshapeMultiBuffer, XtlsPadding, XtlsUnpadding and XtlsFilterTls.
//
// Vision wraps the proxied stream in padding blocks
//
//	[uuid16, first block only] | cmd | contentLen BE[2] | paddingLen BE[2] | content | padding
//
// until the inner TLS handshake is over. cmd 0 = continue, 1 = end of
// padding, 2 = end of padding and switch to "direct": from then on that
// direction carries the inner TLS 1.3 records raw on TCP, without the outer
// TLS layer.
//
// Design choice: no splice(2) / zero-copy. Xray's client hands direct
// traffic to the kernel with splice when both sides are raw TCP sockets; we
// just keep copying through userspace. The *direct* switch itself is not
// optional, though: an Xray server sends cmd 2 whenever it sees inner
// TLS 1.3 and then writes raw bytes, so the reader must follow it. We do that
// without unsafe: the tls/reality layers put a record-aligned RecordConn
// under uTLS (see internal/transport/tls/recordconn.go), so after cmd 2 the
// raw bytes are all still in that conn (Xray instead reads the unexported
// uTLS input/rawInput buffers through reflect+unsafe). For the uplink we do
// switch to direct writes as Xray's client does; that skips double
// encryption on the router.

import (
	"bytes"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
)

// directConn is implemented by *tls.Conn from internal/transport/tls (both
// the tls and the reality layers return it).
type directConn interface {
	TLSVersion() uint16
	DirectReader() io.Reader // raw stream after the last consumed TLS record
	DirectWriter() io.Writer // raw TCP
}

const (
	cmdPaddingContinue = 0x00
	cmdPaddingEnd      = 0x01
	cmdPaddingDirect   = 0x02

	bufSize = 8192 // buf.Size in Xray; Vision block sizes are derived from it
)

var (
	tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	tlsClientHandShakeStart = []byte{0x16, 0x03}
	tlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}
	tlsApplicationDataStart = []byte{0x17, 0x03, 0x03}
)

// testseed defaults from NewVisionWriter: {long-padding threshold, random
// range, base, short random range}.
var testseed = [4]int{900, 500, 900, 256}

// trafficState mirrors proxy.TrafficState, keeping only the client side
// (Outbound) fields.
type trafficState struct {
	mu                     sync.Mutex // reader and writer share the filter state
	userUUID               []byte
	numberOfPacketToFilter int
	enableXtls             bool
	isTLS12orAbove         bool
	isTLS                  bool
	cipher                 uint16
	remainingServerHello   int

	// reader (downlink)
	withinPaddingBuffers bool
	readerDirect         bool
	remainingCommand     int
	remainingContent     int
	remainingPadding     int
	currentCommand       int

	// writer (uplink)
	isPadding    bool
	writerDirect atomic.Bool // read by close()
}

type vision struct {
	conn net.Conn // the outer TLS conn
	dc   directConn
	s    trafficState

	// writer
	w        io.Writer // conn, then the raw TCP after cmd 2
	uuidOnce []byte    // prefixed to the first padding block only

	// reader
	r       io.Reader // conn, then the raw stream after cmd 2
	rbuf    []byte
	pending []byte
	rerr    error
}

func newVision(c net.Conn, dc directConn, id [16]byte) *vision {
	v := &vision{conn: c, dc: dc, w: c, r: c, rbuf: make([]byte, bufSize)}
	v.uuidOnce = append([]byte(nil), id[:]...)
	v.s = trafficState{
		userUUID:               append([]byte(nil), id[:]...),
		numberOfPacketToFilter: 8,
		remainingServerHello:   -1,
		withinPaddingBuffers:   true,
		remainingCommand:       -1,
		remainingContent:       -1,
		remainingPadding:       -1,
		isPadding:              true,
	}
	return v
}

func (v *vision) close() error {
	if v.s.writerDirect.Load() {
		// A TLS close_notify written now would land in the raw stream.
		if nc, ok := v.conn.(interface{ NetConn() net.Conn }); ok {
			return nc.NetConn().Close()
		}
	}
	return v.conn.Close()
}

// ---- writer (VisionWriter.WriteMultiBuffer) ----

// write pads p (split into Xray-sized buffers) and writes prefix (the VLESS
// request header, if not sent yet) plus the result in one Write. p == nil
// with a prefix produces one padding-only block, as Xray does when the
// client sent nothing within 500ms.
func (v *vision) write(prefix, p []byte) (int, error) {
	if v.s.writerDirect.Load() && v.w == v.conn {
		v.w = v.dc.DirectWriter()
	}
	var mb [][]byte
	for rest := p; len(rest) > 0; {
		n := min(len(rest), bufSize)
		mb = append(mb, rest[:n])
		rest = rest[n:]
	}

	v.s.mu.Lock()
	if v.s.numberOfPacketToFilter > 0 {
		v.s.filterTLS(mb)
	}
	isTLS, isTLS12, enableXtls, toFilter := v.s.isTLS, v.s.isTLS12orAbove, v.s.enableXtls, v.s.numberOfPacketToFilter
	v.s.mu.Unlock()

	out := prefix
	if !v.s.isPadding {
		for _, b := range mb {
			out = append(out, b...)
		}
	} else if p == nil {
		out = v.padding(out, nil, cmdPaddingContinue, true)
	} else {
		complete := isCompleteRecord(p)
		mb = reshape(mb)
		longPadding := isTLS
		for i, b := range mb {
			if isTLS && len(b) >= 6 && bytes.HasPrefix(b, tlsApplicationDataStart) && complete {
				if enableXtls {
					v.s.writerDirect.Store(true)
				}
				cmd := byte(cmdPaddingContinue)
				if i == len(mb)-1 {
					cmd = cmdPaddingEnd
					if enableXtls {
						cmd = cmdPaddingDirect
					}
				}
				out = v.padding(out, b, cmd, true)
				v.s.isPadding = false
				longPadding = false
				continue
			} else if !isTLS12 && toFilter <= 1 {
				// "For compatibility with earlier vision receiver, we finish
				// padding 1 packet early". The rest of mb goes out unpadded.
				v.s.isPadding = false
				out = v.padding(out, b, cmdPaddingEnd, longPadding)
				for _, rest := range mb[i+1:] {
					out = append(out, rest...)
				}
				break
			}
			cmd := byte(cmdPaddingContinue)
			if i == len(mb)-1 && !v.s.isPadding {
				cmd = cmdPaddingEnd
				if enableXtls {
					cmd = cmdPaddingDirect
				}
			}
			out = v.padding(out, b, cmd, longPadding)
		}
	}
	if _, err := v.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// padding mirrors XtlsPadding, appending the block to out.
func (v *vision) padding(out, content []byte, cmd byte, long bool) []byte {
	contentLen := len(content)
	var paddingLen int
	if contentLen < testseed[0] && long {
		paddingLen = rand.IntN(testseed[1]) + testseed[2] - contentLen
	} else {
		paddingLen = rand.IntN(testseed[3])
	}
	paddingLen = max(min(paddingLen, bufSize-21-contentLen), 0)
	if v.uuidOnce != nil {
		out = append(out, v.uuidOnce...)
		v.uuidOnce = nil
	}
	out = append(out, cmd, byte(contentLen>>8), byte(contentLen), byte(paddingLen>>8), byte(paddingLen))
	out = append(out, content...)
	return append(out, make([]byte, paddingLen)...)
}

// isCompleteRecord mirrors IsCompleteRecord: b is a whole number of TLS
// application data records (17 03 03 len).
func isCompleteRecord(b []byte) bool {
	for len(b) > 0 {
		if len(b) < 5 || b[0] != 0x17 || b[1] != 0x03 || b[2] != 0x03 {
			return false
		}
		n := int(b[3])<<8 | int(b[4])
		if n == 0 || len(b)-5 < n {
			return false
		}
		b = b[5+n:]
	}
	return true
}

// reshape mirrors ReshapeMultiBuffer: a buffer too big to take a 21-byte
// padding header is split at its last application data record start, or in
// half.
func reshape(mb [][]byte) [][]byte {
	out := make([][]byte, 0, len(mb)+1)
	for _, b := range mb {
		if len(b) < bufSize-21 {
			out = append(out, b)
			continue
		}
		i := bytes.LastIndex(b, tlsApplicationDataStart)
		if i < 21 || i > bufSize-21 {
			i = bufSize / 2
		}
		out = append(out, b[:i], b[i:])
	}
	return out
}

// ---- reader (VisionReader.ReadMultiBuffer) ----

func (v *vision) read(p []byte) (int, error) {
	for len(v.pending) == 0 {
		if v.rerr != nil {
			return 0, v.rerr
		}
		if v.s.readerDirect {
			v.rbuf = nil // not used again; pending is empty here
			return v.r.Read(p)
		}
		n, err := v.r.Read(v.rbuf)
		v.rerr = err
		if n > 0 {
			v.pending = v.process(v.rbuf[:n])
		}
	}
	n := copy(p, v.pending)
	v.pending = v.pending[n:]
	return n, nil
}

// process handles one buffer read from the outer TLS conn.
func (v *vision) process(b []byte) []byte {
	s := &v.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.withinPaddingBuffers || s.numberOfPacketToFilter > 0 {
		b = s.unpadding(b)
		if s.remainingContent > 0 || s.remainingPadding > 0 || s.currentCommand == 0 {
			s.withinPaddingBuffers = true
		} else if s.currentCommand == cmdPaddingEnd {
			s.withinPaddingBuffers = false
		} else if s.currentCommand == cmdPaddingDirect {
			s.withinPaddingBuffers = false
			s.readerDirect = true
		}
	}
	if s.numberOfPacketToFilter > 0 && len(b) > 0 {
		s.filterTLS([][]byte{b})
	}
	if s.readerDirect {
		// Everything after this TLS record is raw on TCP (uTLS has no
		// buffered input left: we read whole records and RecordConn never
		// over-reads).
		v.r = v.dc.DirectReader()
	}
	return b
}

// unpadding mirrors XtlsUnpadding for the downlink. It returns the content
// bytes of b; the parse state carries over between calls.
func (s *trafficState) unpadding(b []byte) []byte {
	if s.remainingCommand == -1 && s.remainingContent == -1 && s.remainingPadding == -1 { // initial state
		if len(b) >= 21 && bytes.Equal(s.userUUID, b[:16]) {
			b = b[16:]
			s.remainingCommand = 5
		} else {
			return b
		}
	}
	var out []byte
	for len(b) > 0 {
		if s.remainingCommand > 0 {
			data := b[0]
			b = b[1:]
			switch s.remainingCommand {
			case 5:
				s.currentCommand = int(data)
			case 4:
				s.remainingContent = int(data) << 8
			case 3:
				s.remainingContent |= int(data)
			case 2:
				s.remainingPadding = int(data) << 8
			case 1:
				s.remainingPadding |= int(data)
			}
			s.remainingCommand--
		} else if s.remainingContent > 0 {
			n := min(s.remainingContent, len(b))
			out = append(out, b[:n]...)
			b = b[n:]
			s.remainingContent -= n
		} else { // remainingPadding > 0
			n := min(s.remainingPadding, len(b))
			b = b[n:]
			s.remainingPadding -= n
		}
		if s.remainingCommand <= 0 && s.remainingContent <= 0 && s.remainingPadding <= 0 { // this block done
			if s.currentCommand == 0 {
				s.remainingCommand = 5
			} else {
				s.remainingCommand = -1 // back to initial state
				s.remainingContent = -1
				s.remainingPadding = -1
				out = append(out, b...) // "shouldn't happen"
				break
			}
		}
	}
	return out
}

// filterTLS mirrors XtlsFilterTls: watch the first packets for the inner
// TLS ClientHello (uplink) and ServerHello (downlink) to learn whether the
// inner connection is TLS 1.3 with a cipher Vision may pass through raw.
func (s *trafficState) filterTLS(mb [][]byte) {
	for _, b := range mb {
		s.numberOfPacketToFilter--
		if len(b) >= 6 {
			if bytes.Equal(tlsServerHandShakeStart, b[:3]) && b[5] == 0x02 { // ServerHello
				s.remainingServerHello = (int(b[3])<<8 | int(b[4])) + 5
				s.isTLS12orAbove = true
				s.isTLS = true
				if len(b) >= 79 && s.remainingServerHello >= 79 {
					sessionIDLen := int(b[43])
					if 43+sessionIDLen+3 <= len(b) {
						s.cipher = uint16(b[43+sessionIDLen+1])<<8 | uint16(b[43+sessionIDLen+2])
					}
				}
			} else if bytes.Equal(tlsClientHandShakeStart, b[:2]) && b[5] == 0x01 { // ClientHello
				s.isTLS = true
			}
		}
		if s.remainingServerHello > 0 {
			end := min(s.remainingServerHello, len(b))
			s.remainingServerHello -= len(b)
			if bytes.Contains(b[:end], tls13SupportedVersions) {
				// TLS 1.3 suites 0x1301-0x1304; TLS_AES_128_CCM_8_SHA256
				// (0x1305) and unknown suites keep the outer TLS.
				if s.cipher >= 0x1301 && s.cipher <= 0x1304 {
					s.enableXtls = true
				}
				s.numberOfPacketToFilter = 0
				return
			} else if s.remainingServerHello <= 0 {
				s.numberOfPacketToFilter = 0 // TLS 1.2
				return
			}
		}
	}
}
