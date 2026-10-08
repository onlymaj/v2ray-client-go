package dns

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Wire-format helpers. Only the fields the forwarder needs are parsed:
// the header, the single question, and the TTL/type of every record.

const (
	headerLen = 12

	typeSOA = 6
	typeOPT = 41

	rcodeNoError  = 0
	rcodeFormErr  = 1
	rcodeServFail = 2
	rcodeNXDomain = 3

	flagQR = 1 << 15
	flagTC = 1 << 9
	flagRD = 1 << 8
	flagRA = 1 << 7

	maxPointers = 64 // guards against pointer loops

	// maxUDPSize caps the EDNS0 payload size honoured for UDP replies
	// (the DNS flag day 2020 value). Larger answers are truncated so the
	// client retries over TCP, whose source cannot be spoofed: this bounds
	// how much a spoofed query can reflect.
	maxUDPSize = 1232
)

var errMalformed = errors.New("dns: malformed message")

type header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func parseHeader(msg []byte) (header, error) {
	if len(msg) < headerLen {
		return header{}, errMalformed
	}
	return header{
		ID:      binary.BigEndian.Uint16(msg[0:]),
		Flags:   binary.BigEndian.Uint16(msg[2:]),
		QDCount: binary.BigEndian.Uint16(msg[4:]),
		ANCount: binary.BigEndian.Uint16(msg[6:]),
		NSCount: binary.BigEndian.Uint16(msg[8:]),
		ARCount: binary.BigEndian.Uint16(msg[10:]),
	}, nil
}

func (h header) rcode() int { return int(h.Flags & 0xf) }

// readName decodes the (possibly compressed) name at off and returns it in
// presentation form without the trailing dot ("" for the root) and the
// offset just past the name as stored at off.
func readName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1
	for ptrs := 0; ; {
		if off >= len(msg) {
			return "", 0, errMalformed
		}
		l := int(msg[off])
		switch l & 0xc0 {
		case 0x00:
			if l == 0 {
				if end < 0 {
					end = off + 1
				}
				return sb.String(), end, nil
			}
			if off+1+l > len(msg) {
				return "", 0, errMalformed
			}
			label := msg[off+1 : off+1+l]
			if !validLabel(label) {
				return "", 0, errMalformed
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(label)
			if sb.Len() > 255 {
				return "", 0, errMalformed
			}
			off += 1 + l
		case 0xc0:
			if off+2 > len(msg) {
				return "", 0, errMalformed
			}
			if ptrs++; ptrs > maxPointers {
				return "", 0, errMalformed
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
		default:
			return "", 0, errMalformed // 0x40/0x80 label types are obsolete
		}
	}
}

// validLabel accepts hostname-like labels only, so the dotted form of a
// name (the cache key) is unambiguous: no '.' or '\' inside a label.
func validLabel(b []byte) bool {
	for _, c := range b {
		switch {
		case 'a' <= c|0x20 && c|0x20 <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '*', c == '/':
		default:
			return false
		}
	}
	return true
}

// skipName returns the offset just past the name at off without decoding
// pointers' targets.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errMalformed
		}
		l := int(msg[off])
		switch l & 0xc0 {
		case 0x00:
			if l == 0 {
				return off + 1, nil
			}
			off += 1 + l
		case 0xc0:
			if off+2 > len(msg) {
				return 0, errMalformed
			}
			return off + 2, nil
		default:
			return 0, errMalformed
		}
	}
}

type question struct {
	Name  string // as sent, without trailing dot
	Type  uint16
	Class uint16
	End   int // offset just past the question section
}

// parseQuestion parses the header and the single question of msg.
func parseQuestion(msg []byte) (header, question, error) {
	h, err := parseHeader(msg)
	if err != nil {
		return h, question{}, err
	}
	if h.QDCount != 1 {
		return h, question{}, errMalformed
	}
	name, off, err := readName(msg, headerLen)
	if err != nil {
		return h, question{}, err
	}
	if off+4 > len(msg) {
		return h, question{}, errMalformed
	}
	return h, question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[off:]),
		Class: binary.BigEndian.Uint16(msg[off+2:]),
		End:   off + 4,
	}, nil
}

// rr is one resource record's location and fixed fields.
type rr struct {
	Section  int // 0 answer, 1 authority, 2 additional
	Type     uint16
	Class    uint16
	TTL      uint32
	TTLOff   int
	RDataOff int
	RDLen    int
}

// parseRecords walks every record after the question section.
func parseRecords(msg []byte, h header, off int) ([]rr, error) {
	counts := [3]int{int(h.ANCount), int(h.NSCount), int(h.ARCount)}
	var out []rr
	for sec, n := range counts {
		for range n {
			var err error
			if off, err = skipName(msg, off); err != nil {
				return nil, err
			}
			if off+10 > len(msg) {
				return nil, errMalformed
			}
			r := rr{
				Section:  sec,
				Type:     binary.BigEndian.Uint16(msg[off:]),
				Class:    binary.BigEndian.Uint16(msg[off+2:]),
				TTL:      binary.BigEndian.Uint32(msg[off+4:]),
				TTLOff:   off + 4,
				RDLen:    int(binary.BigEndian.Uint16(msg[off+8:])),
				RDataOff: off + 10,
			}
			off = r.RDataOff + r.RDLen
			if off > len(msg) {
				return nil, errMalformed
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// udpLimit returns the largest UDP response sent to the client: 512, or
// the EDNS0 OPT payload size if the query carries one, at most maxUDPSize.
func udpLimit(query []byte) int {
	h, q, err := parseQuestion(query)
	if err != nil {
		return 512
	}
	rrs, err := parseRecords(query, h, q.End)
	if err != nil {
		return 512
	}
	for _, r := range rrs {
		if r.Section == 2 && r.Type == typeOPT {
			return min(max(512, int(r.Class)), maxUDPSize)
		}
	}
	return 512
}

// truncate returns resp cut to header + question with TC set, if it is
// longer than limit; otherwise resp unchanged.
func truncate(resp []byte, limit int) []byte {
	if len(resp) <= limit {
		return resp
	}
	h, q, err := parseQuestion(resp)
	end := q.End
	if err != nil {
		end = headerLen
		h.QDCount = 0
	}
	out := append([]byte(nil), resp[:end]...)
	binary.BigEndian.PutUint16(out[2:], h.Flags|flagTC)
	binary.BigEndian.PutUint16(out[4:], h.QDCount)
	clear(out[6:12])
	return out
}

// slipResponse answers a query over the rate limit: header + echoed
// question with TC set, so the client retries over TCP. It is never longer
// than query. Responses and malformed queries get nil (no reply).
func slipResponse(query []byte) []byte {
	h, _, err := parseQuestion(query)
	if err != nil || h.Flags&flagQR != 0 {
		return nil
	}
	return truncate(errorResponse(query, rcodeNoError), 0)
}

// errorResponse builds a header + echoed question reply with rcode.
func errorResponse(query []byte, rcode int) []byte {
	h, q, err := parseQuestion(query)
	end := q.End
	if err != nil {
		end, h.QDCount = headerLen, 0
	}
	out := append([]byte(nil), query[:end]...)
	flags := flagQR | flagRA | (h.Flags & (flagRD | 0x7800)) | uint16(rcode) // keep opcode + RD
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], h.QDCount)
	clear(out[6:12])
	return out
}
