// Package api is the JSON HTTP API behind the web UI (contract: web/API.md).
//
// Every route except /api/login, /api/logout and /api/me needs a session
// cookie. Mutating requests (POST, PUT, PATCH, DELETE) must carry
// Content-Type: application/json, even when they have no body; together with
// the SameSite=Strict cookie this blocks cross-site form posts (CSRF). An
// Origin header on a mutating request must match Host. /api/ requests are
// refused unless Host is an IP literal, localhost or in Options.AllowedHosts,
// which blocks DNS rebinding (a foreign name resolved to this address).
// Paths outside /api/ go to Options.Web.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/events"
	"github.com/onlymaj/v2ray-client-go/internal/share"
)

// Status is the live health of one client.
type Status struct {
	State       string // "up" | "down" | "unknown"
	TCPMs       int    // TCP connect time to the server; 0 = unknown
	DelayMs     int    // full request delay through the proxy; 0 = unknown
	LastError   string
	LastSuccess time.Time
	LastCheck   time.Time
}

// Traffic is the byte counters and current rates (bytes/s) of a target.
type Traffic struct {
	Up       uint64 `json:"up"`
	Down     uint64 `json:"down"`
	UpRate   uint64 `json:"upRate"`
	DownRate uint64 `json:"downRate"`
	Conns    int    `json:"conns"`
}

// Runtime supplies live data. Targets are "total", "client:<id>" or
// "group:<id>". Methods must be safe for concurrent use and return quickly.
type Runtime interface {
	ClientStatus(id string) Status
	Traffic(target string) Traffic
	GroupCurrent(id string) string
	// Series returns the JSON-ready time series ({t, up, down, delay}) of
	// target over rng ("1m" | "1h" | "24h").
	Series(target, rng string) (any, error)
	Connections() any
	// CheckNow starts a health check of the client in the background.
	CheckNow(clientID string)
}

type Options struct {
	Store         *config.Store
	Bus           *events.Bus
	Runtime       Runtime
	AdminPassword string
	Web           http.Handler // serves everything outside /api/
	// AllowedHosts are extra host names (no port) accepted in the Host
	// header of /api/ requests, besides IP literals and localhost.
	AllowedHosts []string
	// Fetch downloads a subscription. Default: HTTP GET, 30s timeout, 4 MB cap.
	Fetch func(ctx context.Context, url string) ([]byte, error)
	// CheckClient reports whether a dialer can be built for c (uuid form,
	// flow, fingerprint, Reality key). Without it, such mistakes are saved
	// and surface only as a dead client. No connection is made.
	CheckClient func(c config.Client) error
}

const (
	maxBody = 4 << 20
	// maxCheckNow caps the immediate health checks started for new
	// clients; the health checker reaches the rest on its schedule.
	maxCheckNow = 50
)

type server struct {
	store *config.Store
	bus   *events.Bus
	rt    Runtime
	web   http.Handler
	fetch func(ctx context.Context, url string) ([]byte, error)
	check func(config.Client) error
	auth  *auth
	hosts map[string]bool
	mux   *http.ServeMux
}

// New builds the handler. It fails if AdminPassword is empty.
func New(opts Options) (http.Handler, error) {
	if opts.Store == nil {
		return nil, errors.New("api: nil store")
	}
	a, err := newAuth(opts.AdminPassword)
	if err != nil {
		return nil, err
	}
	s := &server{
		store: opts.Store, bus: opts.Bus, rt: opts.Runtime, web: opts.Web,
		fetch: opts.Fetch, check: opts.CheckClient, auth: a, hosts: map[string]bool{}, mux: http.NewServeMux(),
	}
	for _, h := range opts.AllowedHosts {
		if h = normHost(h); h != "" {
			s.hosts[h] = true
		}
	}
	if s.rt == nil {
		s.rt = nopRuntime{}
	}
	if s.bus == nil {
		s.bus = events.New()
	}
	if s.fetch == nil {
		s.fetch = defaultFetch
	}
	if s.check == nil {
		s.check = func(config.Client) error { return nil }
	}
	s.routes()
	return s, nil
}

func (s *server) routes() {
	m := s.mux
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("POST /api/logout", s.logout)
	m.HandleFunc("GET /api/me", s.me)

	h := func(pattern string, fn http.HandlerFunc) { m.Handle(pattern, s.requireSession(fn)) }
	h("GET /api/clients", s.listClients)
	h("POST /api/clients", s.createClient)
	h("GET /api/clients/{id}", s.getClient)
	h("PUT /api/clients/{id}", s.putClient)
	h("DELETE /api/clients/{id}", s.deleteClient)
	h("POST /api/clients/{id}/toggle", s.toggleClient)
	h("POST /api/clients/{id}/check", s.checkClient)
	h("GET /api/clients/{id}/link", s.clientLink)

	h("GET /api/groups", s.listGroups)
	h("POST /api/groups", s.createGroup)
	h("GET /api/groups/{id}", s.getGroup)
	h("PUT /api/groups/{id}", s.putGroup)
	h("DELETE /api/groups/{id}", s.deleteGroup)

	h("GET /api/rules", s.getRules)
	h("PUT /api/rules", s.putRules)

	h("POST /api/import", s.importLinks)

	h("GET /api/subscriptions", s.listSubs)
	h("POST /api/subscriptions", s.createSub)
	h("DELETE /api/subscriptions/{id}", s.deleteSub)
	h("POST /api/subscriptions/{id}/refresh", s.refreshSub)

	h("GET /api/settings", s.getSettings)
	h("PUT /api/settings", s.putSettings)

	h("GET /api/stats", s.stats)
	h("GET /api/connections", s.connections)
	h("GET /api/events", s.events)

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not found")
	})
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api" && !strings.HasPrefix(r.URL.Path, "/api/") {
		if s.web == nil {
			http.NotFound(w, r)
			return
		}
		s.web.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !s.hostAllowed(r.Host) {
		writeErr(w, http.StatusForbidden, "host not allowed")
		return
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if o := r.Header.Get("Origin"); o != "" {
			if u, err := url.Parse(o); err != nil || !strings.EqualFold(u.Host, r.Host) {
				writeErr(w, http.StatusForbidden, "cross-origin request")
				return
			}
		}
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
			writeErr(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	}
	s.mux.ServeHTTP(w, r)
}

// normHost lowercases host and strips the port, IPv6 brackets and a
// trailing dot.
func normHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func (s *server) hostAllowed(host string) bool {
	h := normHost(host)
	if h == "" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return h == "localhost" || s.hosts[h]
}

// tooManyLinks reports whether share.ParseBulk stopped at share.MaxLinks;
// the API refuses such input rather than taking the first MaxLinks links.
func tooManyLinks(res share.Result) error {
	// Not only the last error: usable appends its own after ParseBulk's.
	for _, e := range res.Errors {
		if strings.HasPrefix(e.Err, "too many links") {
			return errors.New(e.Err)
		}
	}
	return nil
}

// httpError carries a status code out of a Store.Update callback.
type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func errf(code int, format string, a ...any) error {
	return &httpError{code, fmt.Sprintf(format, a...)}
}

// update wraps Store.Update so that validation failures become 400 and
// other failures (disk writes) become 500.
func (s *server) update(fn func(*config.Config) error) error {
	return s.store.Update(func(c *config.Config) error {
		if err := fn(c); err != nil {
			return err
		}
		if err := c.Validate(); err != nil {
			return &httpError{http.StatusBadRequest, err.Error()}
		}
		return nil
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeError(w http.ResponseWriter, err error) {
	var he *httpError
	if errors.As(err, &he) {
		writeErr(w, he.code, he.msg)
		return
	}
	writeErr(w, http.StatusInternalServerError, err.Error())
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errf(http.StatusBadRequest, "invalid JSON: %v", err)
	}
	return nil
}

// defaultFetch downloads a subscription: 30s timeout, 4 MB cap, at most
// maxRedirects redirects. The URL itself may point anywhere, including the
// LAN (an admin may host a subscription there). A redirect to another host
// may not reach a loopback, link-local, private, CGNAT or unspecified
// address, so a subscription server cannot aim requests at the router or
// the LAN; the check runs on every dial, so DNS rebinding of the redirect
// target does not get around it.
func defaultFetch(ctx context.Context, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v2ray-client-go")
	hc := fetchClient(req.URL.Hostname())
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server answered HTTP %d", resp.StatusCode) // not resp.Status: its text is the server's
	}
	const limit = 4 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("subscription is larger than 4 MB")
	}
	return b, nil
}

const maxRedirects = 3

var errRedirectBlocked = errors.New("redirect to a local or private address refused")

// fetchLookup resolves host names for subscription fetches (a var so tests
// can change answers between lookups).
var fetchLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// fetchClient returns a client for one fetch from origHost. origHost is
// resolved once, on the first dial, and every connection to it in this
// fetch (same-host redirects included) goes to the one address the first
// connection reached, so its DNS cannot be rebound to the LAN mid-fetch. Connections to any other
// host must go to a public address.
func fetchClient(origHost string) *http.Client {
	var (
		mu     sync.Mutex
		pinned []netip.Addr
	)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		same := strings.EqualFold(host, origHost)
		var addrs []netip.Addr
		if a, err := netip.ParseAddr(host); err == nil {
			addrs = []netip.Addr{a}
		} else if same {
			mu.Lock()
			if pinned == nil {
				if pinned, err = fetchLookup(ctx, host); err == nil && len(pinned) == 0 {
					err = fmt.Errorf("no address for %s", host)
				}
				// A name that answers with both public and LAN addresses is
				// the setup for reaching the LAN: refuse it. A name with
				// only LAN addresses is a subscription the admin hosts there.
				if err == nil && mixed(pinned) {
					err = fmt.Errorf("%w: %s resolves to both public and private addresses", errRedirectBlocked, host)
				}
				if err != nil {
					pinned = nil
					mu.Unlock()
					return nil, err
				}
			}
			addrs = pinned
			mu.Unlock()
		} else if addrs, err = fetchLookup(ctx, host); err != nil {
			return nil, err
		}
		d := net.Dialer{Timeout: 10 * time.Second}
		if !same {
			d.Control = publicOnly
		}
		var last error
		for _, a := range addrs {
			c, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				if same && len(addrs) > 1 {
					// Later connections (same-host redirects, to any port)
					// go to this address only. With the whole list pinned,
					// a redirect to a port closed here would fall through
					// to the next address.
					mu.Lock()
					pinned = []netip.Addr{a}
					mu.Unlock()
				}
				return c, nil
			}
			last = err
		}
		if last == nil {
			last = fmt.Errorf("no address for %s", host)
		}
		return nil, last
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("more than %d redirects", maxRedirects)
			}
			host := req.URL.Hostname()
			if strings.EqualFold(host, origHost) {
				return nil
			}
			// Fail early with a clear error; publicOnly enforces it on dial.
			addrs, err := fetchLookup(req.Context(), host)
			if err != nil {
				return err
			}
			for _, a := range addrs {
				if blockedAddr(a) {
					return fmt.Errorf("%w: %s", errRedirectBlocked, host)
				}
			}
			return nil
		},
	}
}

// mixed reports whether addrs holds both blocked and public addresses.
func mixed(addrs []netip.Addr) bool {
	var blocked, public bool
	for _, a := range addrs {
		if blockedAddr(a) {
			blocked = true
		} else {
			public = true
		}
	}
	return blocked && public
}

// publicOnly is a net.Dialer Control hook that refuses blocked addresses.
func publicOnly(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if blockedAddr(ap.Addr()) {
		return fmt.Errorf("%w: %s", errRedirectBlocked, ap.Addr())
	}
	return nil
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64 (checked by its IPv4 part below)
}

// blockedAddr reports whether a is loopback, link-local, private (RFC 1918,
// ULA), CGNAT, multicast or unspecified.
func blockedAddr(a netip.Addr) bool {
	a = a.WithZone("").Unmap() // a zone must not hide a loopback or NAT64 address
	if a.Is6() && blockedPrefixes[2].Contains(a) {
		b := a.As16()
		return blockedAddr(netip.AddrFrom4([4]byte(b[12:])))
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || a.IsPrivate() {
		return true
	}
	return blockedPrefixes[0].Contains(a) || blockedPrefixes[1].Contains(a)
}

type nopRuntime struct{}

func (nopRuntime) ClientStatus(string) Status         { return Status{State: "unknown"} }
func (nopRuntime) Traffic(string) Traffic             { return Traffic{} }
func (nopRuntime) GroupCurrent(string) string         { return "" }
func (nopRuntime) Series(string, string) (any, error) { return []any{}, nil }
func (nopRuntime) Connections() any                   { return []any{} }
func (nopRuntime) CheckNow(string)                    {}
