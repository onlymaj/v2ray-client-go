// Package share parses and exports VLESS/VMess share links (vless://,
// vmess://) and subscription bodies into a protocol-neutral Client.
package share

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Client is a protocol-neutral description of one proxy server.
type Client struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"` // "vless" | "vmess"
	Address    string `json:"address"`
	Port       uint16 `json:"port"`
	ID         string `json:"id"`
	Flow       string `json:"flow,omitempty"`       // vless, e.g. "xtls-rprx-vision"
	Security   string `json:"security,omitempty"`   // vmess cipher: auto, aes-128-gcm, chacha20-poly1305, none, zero
	Encryption string `json:"encryption,omitempty"` // vless, normally "none"

	Network string `json:"network"` // "tcp" | "ws" | "grpc"
	TLS     string `json:"tls"`     // "none" | "tls" | "reality"

	SNI           string   `json:"sni,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	AllowInsecure bool     `json:"allowInsecure,omitempty"`

	PublicKey string `json:"publicKey,omitempty"` // reality
	ShortID   string `json:"shortId,omitempty"`   // reality
	SpiderX   string `json:"spiderX,omitempty"`   // reality

	Path string `json:"path,omitempty"` // ws
	Host string `json:"host,omitempty"` // ws Host header

	ServiceName string `json:"serviceName,omitempty"` // grpc
	MultiMode   bool   `json:"multiMode,omitempty"`   // grpc
	Authority   string `json:"authority,omitempty"`   // grpc
}

// ErrUnsupportedScheme is returned by Parse for links that are not vless://
// or vmess:// (ss://, trojan://, ...). Bulk parsers count these as skipped.
var ErrUnsupportedScheme = errors.New("unsupported link scheme")

// Parse parses a single vless:// or vmess:// link.
func Parse(link string) (Client, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return Client{}, errors.New("not a share link")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return ParseVLESS(link)
	case "vmess":
		return ParseVMess(link)
	}
	return Client{}, fmt.Errorf("%w: %s", ErrUnsupportedScheme, scheme)
}

// Link exports c in its protocol's share-link format.
func (c Client) Link() (string, error) {
	switch c.Protocol {
	case "vless":
		return c.VLESSLink()
	case "vmess":
		return c.VMessLink()
	}
	return "", fmt.Errorf("unknown protocol %q", c.Protocol)
}

// Validate checks that c has the fields every dialer needs and only uses
// supported transports.
func (c *Client) Validate() error {
	switch {
	case c.Protocol != "vless" && c.Protocol != "vmess":
		return fmt.Errorf("unknown protocol %q", c.Protocol)
	case c.Address == "":
		return errors.New("missing address")
	case c.Port == 0:
		return errors.New("missing port")
	case c.ID == "":
		return errors.New("missing id")
	}
	switch c.Network {
	case "tcp", "ws", "grpc":
	default:
		return fmt.Errorf("unsupported network %q", c.Network)
	}
	switch c.TLS {
	case "none", "tls":
	case "reality":
		if c.Protocol != "vless" {
			return errors.New("reality requires vless")
		}
		if c.PublicKey == "" {
			return errors.New("reality requires a public key")
		}
	default:
		return fmt.Errorf("unsupported security %q", c.TLS)
	}
	return nil
}

// ParseVLESS parses vless://uuid@host:port?params#name.
func ParseVLESS(link string) (Client, error) {
	// The fragment is split off by hand: names often contain characters
	// (spaces, emoji, stray '%') that url.Parse would reject.
	link, frag, _ := strings.Cut(link, "#")
	u, err := url.Parse(link)
	if err != nil {
		return Client{}, err
	}
	if !strings.EqualFold(u.Scheme, "vless") {
		return Client{}, errors.New("not a vless link")
	}
	q := u.Query()
	c := Client{
		Name:        unescapeName(frag),
		Protocol:    "vless",
		Address:     u.Hostname(),
		Flow:        q.Get("flow"),
		Encryption:  def(q.Get("encryption"), "none"),
		Network:     normNetwork(q.Get("type")),
		TLS:         def(strings.ToLower(q.Get("security")), "none"),
		SNI:         q.Get("sni"),
		Fingerprint: q.Get("fp"),
		ALPN:        splitList(q.Get("alpn")),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		SpiderX:     q.Get("spx"),
	}
	if u.User != nil {
		c.ID = u.User.Username()
	}
	if c.Port, err = parsePort(u.Port()); err != nil {
		return Client{}, err
	}
	c.AllowInsecure = isTrue(q.Get("allowInsecure")) || isTrue(q.Get("insecure"))
	switch c.Network {
	case "ws":
		c.Path, c.Host = q.Get("path"), q.Get("host")
	case "grpc":
		c.ServiceName = q.Get("serviceName")
		c.MultiMode = q.Get("mode") == "multi"
		c.Authority = q.Get("authority")
	}
	if err := c.Validate(); err != nil {
		return Client{}, err
	}
	return c, nil
}

// VLESSLink exports c as a vless:// link.
func (c Client) VLESSLink() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("type", c.Network)
	set("security", c.TLS)
	set("encryption", def(c.Encryption, "none"))
	set("flow", c.Flow)
	set("sni", c.SNI)
	set("fp", c.Fingerprint)
	set("alpn", strings.Join(c.ALPN, ","))
	if c.AllowInsecure {
		q.Set("allowInsecure", "1")
	}
	set("pbk", c.PublicKey)
	set("sid", c.ShortID)
	set("spx", c.SpiderX)
	switch c.Network {
	case "ws":
		set("path", c.Path)
		set("host", c.Host)
	case "grpc":
		set("serviceName", c.ServiceName)
		set("authority", c.Authority)
		if c.MultiMode {
			q.Set("mode", "multi")
		} else {
			q.Set("mode", "gun")
		}
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(c.ID),
		Host:     net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port))),
		RawQuery: q.Encode(),
		Fragment: c.Name,
	}
	return u.String(), nil
}

// vmessJSON is the v2rayN vmess:// payload. Port and aid are strings or
// numbers depending on the generator.
type vmessJSON struct {
	V    flexString `json:"v"`
	PS   string     `json:"ps"`
	Add  string     `json:"add"`
	Port flexString `json:"port"`
	ID   string     `json:"id"`
	Aid  flexString `json:"aid"`
	Scy  string     `json:"scy,omitempty"`
	Net  string     `json:"net"`
	Type string     `json:"type"`
	Host string     `json:"host"`
	Path string     `json:"path"`
	TLS  string     `json:"tls"`
	SNI  string     `json:"sni,omitempty"`
	ALPN string     `json:"alpn,omitempty"`
	FP   string     `json:"fp,omitempty"`
}

// flexString accepts a JSON string or number.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	if string(b) == "null" {
		*f = ""
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n)
	return nil
}

// ParseVMess parses a v2rayN-style vmess://base64(json) link.
func ParseVMess(link string) (Client, error) {
	scheme, payload, _ := strings.Cut(strings.TrimSpace(link), "://")
	if !strings.EqualFold(scheme, "vmess") {
		return Client{}, errors.New("not a vmess link")
	}
	raw, err := decodeBase64(payload)
	if err != nil {
		return Client{}, errors.New("vmess: payload is not base64 JSON")
	}
	var j vmessJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return Client{}, fmt.Errorf("vmess: %w", err)
	}
	if aid := strings.TrimSpace(string(j.Aid)); aid != "" && aid != "0" {
		return Client{}, errors.New("legacy vmess not supported (alterId must be 0)")
	}
	c := Client{
		Name:        j.PS,
		Protocol:    "vmess",
		Address:     j.Add,
		ID:          j.ID,
		Security:    def(j.Scy, "auto"),
		Network:     normNetwork(j.Net),
		TLS:         def(strings.ToLower(j.TLS), "none"),
		SNI:         j.SNI,
		Fingerprint: j.FP,
		ALPN:        splitList(j.ALPN),
	}
	if c.Port, err = parsePort(strings.TrimSpace(string(j.Port))); err != nil {
		return Client{}, err
	}
	switch c.Network {
	case "tcp":
		if j.Type != "" && j.Type != "none" {
			return Client{}, fmt.Errorf("vmess: tcp header %q not supported", j.Type)
		}
	case "ws":
		c.Path, c.Host = j.Path, j.Host
	case "grpc":
		// v2rayN stores serviceName in path, mode in type, authority in host.
		c.ServiceName, c.Authority = j.Path, j.Host
		c.MultiMode = j.Type == "multi"
	}
	if err := c.Validate(); err != nil {
		return Client{}, err
	}
	return c, nil
}

// VMessLink exports c as a v2rayN-style vmess:// link.
func (c Client) VMessLink() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	j := vmessJSON{
		V: "2", PS: c.Name, Add: c.Address, Port: flexString(strconv.Itoa(int(c.Port))),
		ID: c.ID, Aid: "0", Scy: c.Security, Net: c.Network, Type: "none",
		SNI: c.SNI, ALPN: strings.Join(c.ALPN, ","), FP: c.Fingerprint,
	}
	if c.TLS == "tls" {
		j.TLS = "tls"
	}
	switch c.Network {
	case "ws":
		j.Path, j.Host = c.Path, c.Host
	case "grpc":
		j.Path, j.Host = c.ServiceName, c.Authority
		j.Type = "gun"
		if c.MultiMode {
			j.Type = "multi"
		}
	}
	b, err := json.Marshal(j)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
}

// LineError reports a link that looked supported but failed to parse.
type LineError struct {
	Line int    `json:"line"` // 1-based
	Text string `json:"text"`
	Err  string `json:"error"`
}

// Result is the outcome of parsing a list of links.
type Result struct {
	Clients []Client    `json:"clients"`
	Errors  []LineError `json:"errors,omitempty"`
	Skipped int         `json:"skipped"` // lines with unsupported schemes (ss://, trojan://, ...)
}

// ParseBulk parses one link per line. Blank lines and comments (# or //)
// are ignored, unsupported schemes are counted as skipped, and lines that
// fail to parse are reported in Result.Errors.
func ParseBulk(text string) Result {
	var r Result
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		c, err := Parse(line)
		switch {
		case err == nil:
			r.Clients = append(r.Clients, c)
		case errors.Is(err, ErrUnsupportedScheme) || !strings.Contains(line, "://"):
			r.Skipped++
		default:
			r.Errors = append(r.Errors, LineError{Line: i + 1, Text: line, Err: err.Error()})
		}
	}
	return r
}

// DecodeSubscription parses a subscription body: base64 (std or URL
// alphabet, padded or not, possibly wrapped) of a newline-separated link
// list, or the plain list itself.
func DecodeSubscription(body []byte) Result {
	if b, err := decodeBase64(string(body)); err == nil && strings.Contains(string(b), "://") {
		return ParseBulk(string(b))
	}
	return ParseBulk(string(body))
}

// decodeBase64 accepts any of the four base64 variants, ignoring whitespace.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	enc := base64.StdEncoding
	if strings.ContainsAny(s, "-_") {
		enc = base64.URLEncoding
	}
	if !strings.HasSuffix(s, "=") {
		enc = enc.WithPadding(base64.NoPadding)
	}
	return enc.DecodeString(s)
}

func normNetwork(n string) string {
	switch n = strings.ToLower(n); n {
	case "", "raw":
		return "tcp"
	case "gun":
		return "grpc"
	}
	return n
}

func parsePort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(p), nil
}

func unescapeName(s string) string {
	if n, err := url.PathUnescape(s); err == nil {
		return n
	}
	return s
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func isTrue(s string) bool { return s == "1" || strings.EqualFold(s, "true") }

func def(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
