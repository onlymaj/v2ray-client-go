// Package share parses and exports VLESS/VMess share links (vless://,
// vmess://) and subscription bodies into a protocol-neutral Client.
package share

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"
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

	SNI         string   `json:"sni,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	// AllowInsecure is never read from or written to a link: a link author
	// could otherwise turn off certificate checks unnoticed (Xray dropped
	// allowInsecure too). Only the admin can set it on a client.
	AllowInsecure bool `json:"allowInsecure,omitempty"`

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
	// Before anything is split, decoded or quoted into an error: one link
	// of 2 MiB with an alpn of commas became 32 MiB of list entries, and
	// an oversized field quoted in an error 47 MiB (round 20).
	if len(link) > MaxLinkLen {
		return Client{}, fmt.Errorf("link is longer than %d bytes", MaxLinkLen)
	}
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

// maxFieldLen bounds every free-text field of a client.
const maxFieldLen = 1024

// maxNameLen bounds a client's name.
const maxNameLen = 256

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
	// Every string must be valid UTF-8: JSON export (vmess links, the API)
	// would otherwise silently replace bytes and change the client.
	for _, v := range append([]string{c.Name, c.Protocol, c.Address, c.ID, c.Flow, c.Security, c.Encryption,
		c.Network, c.TLS, c.SNI, c.Fingerprint, c.PublicKey, c.ShortID, c.SpiderX, c.Path, c.Host,
		c.ServiceName, c.Authority}, c.ALPN...) {
		if !utf8.ValidString(v) {
			return errors.New("invalid UTF-8 in link")
		}
	}
	// Everything here is stored in config.json and returned by the API; a
	// subscription must not be able to store megabytes in one field.
	for _, v := range []string{c.Name, c.ID, c.Flow, c.Security, c.Encryption, c.SNI, c.Fingerprint,
		c.PublicKey, c.ShortID, c.SpiderX, c.Path, c.Host, c.ServiceName, c.Authority} {
		if len(v) > maxFieldLen {
			return fmt.Errorf("field too long (%d bytes, limit %d)", len(v), maxFieldLen)
		}
	}
	// The name is shown, not used: it needs far less, and 1000 clients with
	// 1 KiB names are a megabyte in every config save and client list.
	if len(c.Name) > maxNameLen {
		return fmt.Errorf("name too long (%d bytes, limit %d)", len(c.Name), maxNameLen)
	}
	if len(c.ALPN) > 8 {
		return errors.New("too many alpn values")
	}
	if !validAddress(c.Address) {
		return fmt.Errorf("invalid address %q", c.Address)
	}
	// VLESS encryption (e.g. mlkem768x25519plus) is not implemented. Refuse
	// it instead of silently sending the header and first payload in the
	// clear to a server that expects it encrypted.
	if c.Protocol == "vless" && c.Encryption != "" && c.Encryption != "none" {
		return fmt.Errorf("vless encryption %q is not supported", c.Encryption)
	}
	// The dialer lowercases the VMess cipher, so "NONE" would send plaintext
	// while the UI, comparing exactly, showed no "unencrypted" warning.
	// Store the canonical form and refuse ciphers the dialer doesn't know.
	if c.Protocol == "vmess" {
		c.Security = strings.ToLower(c.Security)
		switch c.Security {
		case "", "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
		default:
			return fmt.Errorf("unsupported vmess security %q", c.Security)
		}
	}
	// Short identifier fields are stored and shown in the UI; refuse control
	// characters so a subscription can't save garbage.
	for _, f := range []struct{ name, v string }{
		{"id", c.ID}, {"name", c.Name}, {"flow", c.Flow}, {"security", c.Security}, {"encryption", c.Encryption},
		{"fingerprint", c.Fingerprint}, {"publicKey", c.PublicKey}, {"shortId", c.ShortID},
	} {
		if hasCtl(f.v) {
			return fmt.Errorf("invalid %s %q", f.name, f.v)
		}
	}
	// Values below end up in dial targets, HTTP request lines and headers.
	for _, f := range []struct{ name, v string }{
		{"address", c.Address}, {"sni", c.SNI}, {"host", c.Host}, {"authority", c.Authority}, {"path", c.Path},
	} {
		if hasCtlOrSpace(f.v) {
			return fmt.Errorf("invalid %s %q", f.name, f.v)
		}
	}
	for _, f := range []struct{ name, v string }{{"host", c.Host}, {"authority", c.Authority}} {
		if f.v != "" && !httpguts.ValidHostHeader(f.v) {
			return fmt.Errorf("invalid %s %q", f.name, f.v)
		}
	}
	for _, f := range []struct{ name, v string }{{"serviceName", c.ServiceName}, {"spiderX", c.SpiderX}} {
		if hasCtl(f.v) {
			return fmt.Errorf("invalid %s %q", f.name, f.v)
		}
	}
	for _, a := range c.ALPN {
		if a == "" || len(a) > 255 || hasCtlOrSpace(a) || strings.Contains(a, ",") {
			return fmt.Errorf("invalid alpn %q", a)
		}
	}
	return nil
}

// validAddress accepts an IP literal (IPv6 without brackets) or a host name
// made of letters, digits, '-', '_' and '.'.
func validAddress(a string) bool {
	if a == "" || len(a) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(a); err == nil {
		return true
	}
	for _, r := range a {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func hasCtl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7F })
}

func hasCtlOrSpace(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7F })
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
	// Not u.Query(): it drops what it cannot parse (a pair with ';' or a
	// bad escape, or everything past 10,000 pairs), and with it settings
	// the checks below must see, such as security= or pcs=.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Client{}, fmt.Errorf("invalid link parameters: %w", err)
	}
	// REALITY post-quantum verification (pqv / mldsa65Verify) is not
	// implemented: refuse rather than silently drop a check the link's
	// author asked for.
	if q.Get("pqv") != "" {
		return Client{}, errors.New("reality pqv (ML-DSA-65 verification) is not supported")
	}
	// The same goes for TLS settings that are not implemented: a pinned
	// certificate (pcs), verification by another name (vcn) and encrypted
	// client hello (ech). Dropping them would give a weaker connection
	// than the link asks for, with no sign of it.
	for _, k := range []string{"pcs", "vcn", "ech"} {
		if q.Get(k) != "" {
			return Client{}, fmt.Errorf("tls setting %q is not supported", k)
		}
	}
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
	switch c.Network {
	case "tcp":
		// HTTP header obfuscation is not implemented (the VMess parser
		// refuses it too).
		if t := q.Get("headerType"); t != "" && t != "none" {
			return Client{}, fmt.Errorf("vless: tcp header %q not supported", t)
		}
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

// MaxLinks bounds the links ParseBulk and DecodeSubscription accept.
const MaxLinks = 1000

// MaxLinkLen bounds one share link. The fields of a client are limited to
// about 1 KiB each, so a real link is far below this.
const MaxLinkLen = 16 << 10

// maxErrorText bounds LineError.Text.
const maxErrorText = 256

// ParseBulk parses one link per line. Blank lines and comments (# or //)
// are ignored, unsupported schemes are counted as skipped, and lines that
// fail to parse are reported in Result.Errors. Parsing stops with a
// "too many links" error after MaxLinks links.
func ParseBulk(text string) Result {
	var r Result
	links := 0
	// Line by line without strings.Split: a 4 MB body of newlines would
	// become 4 million string headers (64 MB) before MaxLinks is checked.
	for i, rest, more := 0, text, true; more; i++ {
		var line string
		line, rest, more = strings.Cut(rest, "\n")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if links++; links > MaxLinks {
			r.Errors = append(r.Errors, LineError{Line: i + 1, Text: clip(line), Err: fmt.Sprintf("too many links (max %d)", MaxLinks)})
			break
		}
		c, err := Parse(line)
		switch {
		case err == nil:
			r.Clients = append(r.Clients, c)
		case errors.Is(err, ErrUnsupportedScheme) || !strings.Contains(line, "://"):
			r.Skipped++
		default:
			r.Errors = append(r.Errors, LineError{Line: i + 1, Text: clip(line), Err: clip(err.Error())})
		}
	}
	return r
}

// DecodeSubscription parses a subscription body: base64 (std or URL
// alphabet, padded or not, possibly wrapped) of a newline-separated link
// list, or the plain list itself.
//
// body is modified. A body of megabytes is not copied more often than
// needed: it came from a server.
func DecodeSubscription(body []byte) Result {
	if bytes.Contains(body, []byte("://")) { // ':' is not in any base64 alphabet
		return ParseBulk(string(body))
	}
	n := 0
	for _, c := range body {
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			body[n] = c
			n++
		}
	}
	body = body[:n]
	enc := base64.StdEncoding
	if bytes.ContainsAny(body, "-_") {
		enc = base64.URLEncoding
	}
	if !bytes.HasSuffix(body, []byte("=")) {
		enc = enc.WithPadding(base64.NoPadding)
	}
	dec := make([]byte, enc.DecodedLen(len(body)))
	if n, err := enc.Decode(dec, body); err == nil && bytes.Contains(dec[:n], []byte("://")) {
		return ParseBulk(string(dec[:n]))
	}
	return Result{Skipped: 1} // neither links nor base64 of links
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

func clip(s string) string {
	if len(s) > maxErrorText {
		return s[:maxErrorText] + "..."
	}
	return s
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

func def(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
