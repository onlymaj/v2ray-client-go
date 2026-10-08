// Package api is the JSON HTTP API behind the web UI (contract: web/API.md).
//
// Every route except /api/login, /api/logout and /api/me needs a session
// cookie. Mutating requests (POST, PUT, PATCH, DELETE) must carry
// Content-Type: application/json, even when they have no body; together with
// the SameSite=Strict cookie this blocks cross-site form posts (CSRF).
// Paths outside /api/ go to Options.Web.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/events"
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
	// Fetch downloads a subscription. Default: HTTP GET, 30s timeout, 4 MB cap.
	Fetch func(ctx context.Context, url string) ([]byte, error)
}

const maxBody = 4 << 20

type server struct {
	store *config.Store
	bus   *events.Bus
	rt    Runtime
	web   http.Handler
	fetch func(ctx context.Context, url string) ([]byte, error)
	auth  *auth
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
		fetch: opts.Fetch, auth: a, mux: http.NewServeMux(),
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
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
			writeErr(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	}
	s.mux.ServeHTTP(w, r)
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

func defaultFetch(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v2ray-client-go")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
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

type nopRuntime struct{}

func (nopRuntime) ClientStatus(string) Status         { return Status{State: "unknown"} }
func (nopRuntime) Traffic(string) Traffic             { return Traffic{} }
func (nopRuntime) GroupCurrent(string) string         { return "" }
func (nopRuntime) Series(string, string) (any, error) { return []any{}, nil }
func (nopRuntime) Connections() any                   { return []any{} }
func (nopRuntime) CheckNow(string)                    {}
