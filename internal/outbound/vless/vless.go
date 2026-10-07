//go:build vless

// Package vless is the VLESS outbound (TCP only), optionally with the
// xtls-rprx-vision flow. Wire format mirrors proxy/vless/encoding in Xray:
//
//	request:  version(0) | uuid[16] | addonsLen | addons | cmd | port BE[2] | atyp | addr
//	response: version(0) | addonsLen | addons
//
// Addons is the protobuf message proxy/vless/encoding/addons.proto
// (field 1 Flow string, field 2 Seed bytes), encoded here by hand.
package vless

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

const (
	version    = 0
	cmdTCP     = 0x01 // protocol.RequestCommandTCP
	FlowVision = "xtls-rprx-vision"

	// Address types used by VLESS (common/protocol/payload.go).
	atypIPv4   = 1
	atypDomain = 2
	atypIPv6   = 3
)

type Settings struct {
	ID   string `json:"id"`   // user UUID
	Flow string `json:"flow"` // "" or "xtls-rprx-vision"
}

type dialer struct {
	id   [16]byte
	flow string
	dial func(ctx context.Context) (net.Conn, error)
}

func init() {
	outbound.Register("vless", New)
}

func New(settings []byte, dialTransport func(ctx context.Context) (net.Conn, error)) (outbound.Dialer, error) {
	var s Settings
	if err := json.Unmarshal(settings, &s); err != nil {
		return nil, err
	}
	id, err := ParseUUID(s.ID)
	if err != nil {
		return nil, err
	}
	switch s.Flow {
	case "":
	case FlowVision, FlowVision + "-udp443": // -udp443 only matters for UDP; Xray strips it
		s.Flow = FlowVision
	default:
		return nil, errors.New("vless: unsupported flow " + s.Flow)
	}
	return &dialer{id: id, flow: s.Flow, dial: dialTransport}, nil
}

// ParseUUID parses the canonical 8-4-4-4-12 hex form. (Xray also accepts
// arbitrary strings mapped through UUIDv5; not supported here.)
func ParseUUID(s string) (id [16]byte, err error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, errors.New("vless: bad uuid")
	}
	h := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if _, err := hex.Decode(id[:], []byte(h)); err != nil {
		return id, errors.New("vless: bad uuid")
	}
	return id, nil
}

// EncodeAddons mirrors EncodeHeaderAddons: only the Vision flow is sent;
// any other flow is encoded as an empty addons block.
func EncodeAddons(b []byte, flow string) []byte {
	if flow != FlowVision {
		return append(b, 0)
	}
	// protobuf: tag (field 1, wire type 2) = 0x0a, varint length, bytes.
	// len(flow) < 128 so the varint is one byte.
	b = append(b, byte(2+len(flow)), 0x0a, byte(len(flow)))
	return append(b, flow...)
}

// EncodeRequestHeader mirrors encoding.EncodeRequestHeader for a TCP
// request, with the port-first address layout of addrParser.
func EncodeRequestHeader(id [16]byte, flow string, dest outbound.Addr) ([]byte, error) {
	b := make([]byte, 0, 64+len(dest.Domain))
	b = append(b, version)
	b = append(b, id[:]...)
	b = EncodeAddons(b, flow)
	b = append(b, cmdTCP, byte(dest.Port>>8), byte(dest.Port))
	switch {
	case dest.Domain != "":
		if len(dest.Domain) > 255 {
			return nil, errors.New("vless: domain too long")
		}
		b = append(b, atypDomain, byte(len(dest.Domain)))
		b = append(b, dest.Domain...)
	case dest.IP.Unmap().Is4():
		ip := dest.IP.Unmap().As4()
		b = append(b, atypIPv4)
		b = append(b, ip[:]...)
	case dest.IP.Is6():
		ip := dest.IP.As16()
		b = append(b, atypIPv6)
		b = append(b, ip[:]...)
	default:
		return nil, errors.New("vless: empty destination")
	}
	return b, nil
}

// DecodeResponseHeader mirrors encoding.DecodeResponseHeader. The response
// addons are skipped: Xray servers send none.
func DecodeResponseHeader(r io.Reader) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != version {
		return errors.New("vless: unexpected response version")
	}
	if b[1] > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(b[1])); err != nil {
			return err
		}
	}
	return nil
}

func (d *dialer) Dial(ctx context.Context, network string, dest outbound.Addr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("vless: only tcp is supported")
	}
	header, err := EncodeRequestHeader(d.id, d.flow, dest)
	if err != nil {
		return nil, err
	}
	c, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	vc := &conn{Conn: c, header: header, sent: make(chan struct{})}
	if d.flow == FlowVision {
		dc, ok := c.(directConn)
		if !ok {
			c.Close()
			return nil, errors.New("vless: xtls-rprx-vision needs the tls or reality transport directly")
		}
		if dc.TLSVersion() != 0x0304 {
			c.Close()
			return nil, errors.New("vless: xtls-rprx-vision needs outer TLS 1.3")
		}
		vc.vision = newVision(c, dc, d.id)
	}
	return vc, nil
}

// conn sends the request header with the first Write (like Xray, which
// buffers the header until the first payload) and reads the response header
// before the first Read.
type conn struct {
	net.Conn
	vision *vision

	wmu    sync.Mutex
	header []byte // nil once sent
	sent   chan struct{}

	rmu      sync.Mutex
	respDone bool
}

func (c *conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeLocked(p)
}

func (c *conn) writeLocked(p []byte) (int, error) {
	prefix := c.header
	if prefix != nil {
		c.header = nil
		defer close(c.sent)
	}
	if c.vision != nil {
		return c.vision.write(prefix, p)
	}
	if prefix != nil {
		if _, err := c.Conn.Write(append(prefix, p...)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.respDone {
		// Server-speaks-first protocols never Write: as in Xray's
		// postRequest, wait 500ms for a payload, then send the header alone
		// (Vision adds a padding-only block to hide its length).
		select {
		case <-c.sent:
		case <-time.After(500 * time.Millisecond):
			c.wmu.Lock()
			var err error
			if c.header != nil {
				_, err = c.writeLocked(nil)
			}
			c.wmu.Unlock()
			if err != nil {
				return 0, err
			}
		}
		if err := DecodeResponseHeader(c.Conn); err != nil {
			return 0, err
		}
		c.respDone = true
	}
	if c.vision != nil {
		return c.vision.read(p)
	}
	return c.Conn.Read(p)
}

func (c *conn) Close() error {
	if c.vision != nil {
		return c.vision.close()
	}
	return c.Conn.Close()
}
