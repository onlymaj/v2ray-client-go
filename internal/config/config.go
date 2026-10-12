// Package config holds the persisted configuration (clients, groups, rules,
// subscriptions, settings) and a Store that writes it atomically (temp file
// + rename) only when it changes. JSON field names are the API contract in
// web/API.md.
package config

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/router"
	"github.com/onlymaj/v2ray-client-go/internal/share"
)

// Client is one proxy client (outbound). Runtime state (status, traffic)
// is not persisted; the API adds it to responses.
type Client struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	// Untrusted marks clients created from pasted share links or a
	// subscription. They get the same server-address restrictions as
	// subscription clients until the admin saves them through the form.
	Untrusted bool `json:"untrusted,omitempty"`

	Protocol string `json:"protocol"` // "vless" | "vmess"
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	UUID     string `json:"uuid"`
	Flow     string `json:"flow,omitempty"`
	Security string `json:"security,omitempty"` // vmess cipher

	Network string `json:"network"` // "tcp" | "ws" | "grpc"
	TLS     string `json:"tls"`     // "none" | "tls" | "reality"

	SNI           string   `json:"sni,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	AllowInsecure bool     `json:"allowInsecure,omitempty"`

	PublicKey string `json:"publicKey,omitempty"`
	ShortID   string `json:"shortId,omitempty"`
	SpiderX   string `json:"spiderX,omitempty"`

	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`

	ServiceName string `json:"serviceName,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
	Authority   string `json:"authority,omitempty"`
}

// FromShare converts a parsed share link into a new, enabled client.
func FromShare(s share.Client) Client {
	return Client{
		ID: NewID(), Name: s.Name, Enabled: true,
		Protocol: s.Protocol, Address: s.Address, Port: s.Port, UUID: s.ID,
		Flow: s.Flow, Security: s.Security, Network: s.Network, TLS: s.TLS,
		SNI: s.SNI, Fingerprint: s.Fingerprint, ALPN: s.ALPN, AllowInsecure: s.AllowInsecure,
		PublicKey: s.PublicKey, ShortID: s.ShortID, SpiderX: s.SpiderX,
		Path: s.Path, Host: s.Host,
		ServiceName: s.ServiceName, MultiMode: s.MultiMode, Authority: s.Authority,
	}
}

// Share converts back for exporting a share link.
func (c Client) Share() share.Client {
	return share.Client{
		Name: c.Name, Protocol: c.Protocol, Address: c.Address, Port: c.Port, ID: c.UUID,
		Flow: c.Flow, Security: c.Security, Encryption: "none", Network: c.Network, TLS: c.TLS,
		SNI: c.SNI, Fingerprint: c.Fingerprint, ALPN: c.ALPN, AllowInsecure: c.AllowInsecure,
		PublicKey: c.PublicKey, ShortID: c.ShortID, SpiderX: c.SpiderX,
		Path: c.Path, Host: c.Host,
		ServiceName: c.ServiceName, MultiMode: c.MultiMode, Authority: c.Authority,
	}
}

type Subscription struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	LastUpdate string `json:"lastUpdate,omitempty"` // RFC3339
	Count      int    `json:"count"`
	LastError  string `json:"lastError,omitempty"`
	// Note says what a successful refresh left out or kept. It is not an
	// error: the refresh was applied.
	Note string `json:"note,omitempty"`
}

type Ports struct {
	Transparent uint16 `json:"transparent"`
	SOCKS       uint16 `json:"socks"` // 0 disables
	HTTP        uint16 `json:"http"`  // 0 disables
	DNS         uint16 `json:"dns"`   // 0 disables
	UI          uint16 `json:"ui"`
}

type RouterOS struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"` // e.g. https://172.17.0.1
	User        string `json:"user"`
	Password    string `json:"password,omitempty"` // never returned by the API
	AddressList string `json:"addressList"`
	// CertSHA256 pins the RouterOS HTTPS certificate (hex SHA-256 of the
	// DER leaf). Empty means the certificate is not verified.
	CertSHA256 string `json:"certSha256,omitempty"`
}

const (
	KillSwitchBlock  = "block"
	KillSwitchDirect = "direct"
)

type Settings struct {
	Ports          Ports  `json:"ports"`
	HealthURL      string `json:"healthUrl"`
	HealthInterval int    `json:"healthInterval"` // seconds
	KillSwitch     string `json:"killSwitch"`     // "block" | "direct"
	DNSUpstream    string `json:"dnsUpstream"`    // ip:port queried over TCP through the proxy
	// AllowPrivateServers lets untrusted clients (from a subscription or
	// pasted share links) use private/CGNAT server addresses. Off by
	// default: such a link could otherwise point health checks at LAN
	// devices. Clients saved through the form may always use them; loopback, link-local, the container and its
	// gateway are always refused.
	AllowPrivateServers bool     `json:"allowPrivateServers,omitempty"`
	RouterOS            RouterOS `json:"routeros"`
}

// Config is the whole persisted document.
type Config struct {
	Clients       []Client       `json:"clients"`
	Groups        []group.Group  `json:"groups"`
	Rules         []router.Rule  `json:"rules"`
	Subscriptions []Subscription `json:"subscriptions"`
	Settings      Settings       `json:"settings"`
}

// Default returns the config used on first start: no clients, one empty
// failover group as the default route.
func Default() *Config {
	return &Config{
		Clients:       []Client{},
		Groups:        []group.Group{{ID: "default", Name: "Default", Strategy: group.Failover, Members: []string{}}},
		Rules:         []router.Rule{{ID: "default", Type: "default", Target: router.Target{Kind: router.KindGroup, ID: "default"}}},
		Subscriptions: []Subscription{},
		Settings: Settings{
			// SOCKS and HTTP CONNECT are off by default: they have no
			// authentication, so any LAN device could use them.
			Ports:          Ports{Transparent: 12345, SOCKS: 0, HTTP: 0, DNS: 53, UI: 80},
			HealthURL:      "https://www.gstatic.com/generate_204",
			HealthInterval: 60,
			KillSwitch:     KillSwitchBlock,
			DNSUpstream:    "1.1.1.1:53",
			RouterOS:       RouterOS{URL: "https://172.17.0.1", AddressList: "no-proxy"},
		},
	}
}

// NewID returns a short random hex ID.
func NewID() string {
	var b [6]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Client returns the client with id, or nil.
func (c *Config) Client(id string) *Client {
	for i := range c.Clients {
		if c.Clients[i].ID == id {
			return &c.Clients[i]
		}
	}
	return nil
}

// Group returns the group with id, or nil.
func (c *Config) Group(id string) *group.Group {
	for i := range c.Groups {
		if c.Groups[i].ID == id {
			return &c.Groups[i]
		}
	}
	return nil
}
