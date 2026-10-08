package api

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/events"
	"github.com/onlymaj/v2ray-client-go/internal/router"
	"github.com/onlymaj/v2ray-client-go/internal/share"
)

func init() { scryptN = 1024 } // keep tests fast

type fakeRT struct {
	mu      sync.Mutex
	checked []string
}

func (f *fakeRT) ClientStatus(id string) Status {
	return Status{State: "up", TCPMs: 12, DelayMs: 80, LastCheck: time.Unix(1700000000, 0)}
}
func (f *fakeRT) Traffic(target string) Traffic { return Traffic{Up: 1, Down: 2, Conns: 3} }
func (f *fakeRT) GroupCurrent(id string) string { return "cur-" + id }
func (f *fakeRT) Series(target, rng string) (any, error) {
	return map[string]any{"target": target, "range": rng}, nil
}
func (f *fakeRT) Connections() any { return []string{"c1"} }
func (f *fakeRT) CheckNow(id string) {
	f.mu.Lock()
	f.checked = append(f.checked, id)
	f.mu.Unlock()
}

type env struct {
	t      *testing.T
	srv    *httptest.Server
	store  *config.Store
	bus    *events.Bus
	cookie *http.Cookie
	rt     *fakeRT
	mu     sync.Mutex
	subs   map[string]string // url -> body for the fake fetch
}

func (e *env) setSub(url, body string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if body == "" {
		delete(e.subs, url)
	} else {
		e.subs[url] = body
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, store: st, bus: events.New(), rt: &fakeRT{}, subs: map[string]string{}}
	h, err := New(Options{
		Store: st, Bus: e.bus, Runtime: e.rt, AdminPassword: "s3cret",
		Web: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ui") }),
		Fetch: func(ctx context.Context, url string) ([]byte, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			b, ok := e.subs[url]
			if !ok {
				return nil, errors.New("404")
			}
			return []byte(b), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(method, path string, body any) (*http.Response, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	if e.cookie != nil {
		req.AddCookie(e.cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (e *env) expect(method, path string, body any, code int, into any) {
	e.t.Helper()
	resp, out := e.do(method, path, body)
	if resp.StatusCode != code {
		e.t.Fatalf("%s %s: got %d want %d: %s", method, path, resp.StatusCode, code, out)
	}
	if into != nil {
		if err := json.Unmarshal(out, into); err != nil {
			e.t.Fatalf("%s %s: %v: %s", method, path, err, out)
		}
	}
}

func (e *env) login() {
	e.t.Helper()
	resp, out := e.do("POST", "/api/login", map[string]string{"password": "s3cret"})
	if resp.StatusCode != 204 {
		e.t.Fatalf("login: %d %s", resp.StatusCode, out)
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			e.cookie = c
		}
	}
	if e.cookie == nil {
		e.t.Fatal("no session cookie")
	}
}

func link(t *testing.T, name, addr string, port uint16, uuid string) string {
	t.Helper()
	l, err := share.Client{Name: name, Protocol: "vless", Address: addr, Port: port, ID: uuid,
		Encryption: "none", Network: "ws", TLS: "tls", SNI: addr, Path: "/ws"}.Link()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

const (
	u1 = "11111111-1111-1111-1111-111111111111"
	u2 = "22222222-2222-2222-2222-222222222222"
	u3 = "33333333-3333-3333-3333-333333333333"
)

func TestNewRequiresPassword(t *testing.T) {
	st, _ := config.Open(filepath.Join(t.TempDir(), "c.json"))
	if _, err := New(Options{Store: st}); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestAuthFlow(t *testing.T) {
	e := newEnv(t)
	e.expect("GET", "/api/me", nil, 401, nil)
	e.expect("GET", "/api/clients", nil, 401, nil)
	e.expect("POST", "/api/login", map[string]string{"password": "nope"}, 401, nil)

	resp, _ := e.do("POST", "/api/login", map[string]string{"password": "s3cret"})
	if resp.StatusCode != 204 {
		t.Fatal(resp.Status)
	}
	c := resp.Cookies()[0]
	if c.Name != cookieName || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Secure {
		t.Fatalf("bad cookie %+v", c)
	}
	e.cookie = c
	e.expect("GET", "/api/me", nil, 200, nil)
	e.expect("GET", "/api/clients", nil, 200, nil)

	// Non-JSON mutating request is refused even with a session.
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/logout", strings.NewReader("x"))
	req.Header.Set("Content-Type", "text/plain")
	req.AddCookie(e.cookie)
	r2, _ := http.DefaultClient.Do(req)
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("csrf: %d", r2.StatusCode)
	}

	e.expect("POST", "/api/logout", nil, 204, nil)
	e.expect("GET", "/api/me", nil, 401, nil)

	// Non-API paths go to the UI handler.
	resp, out := e.do("GET", "/index.html", nil)
	if resp.StatusCode != 200 || string(out) != "ui" {
		t.Fatalf("web: %d %q", resp.StatusCode, out)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < loginAttempts; i++ {
		e.expect("POST", "/api/login", map[string]string{"password": "bad"}, 401, nil)
	}
	resp, _ := e.do("POST", "/api/login", map[string]string{"password": "s3cret"})
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("got %d retry-after=%q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

func TestRateLimitWindow(t *testing.T) {
	a, err := newAuth("pw")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	a.now = func() time.Time { return now }
	for i := 0; i < loginAttempts; i++ {
		if ok, _ := a.begin("1.2.3.4"); !ok {
			t.Fatalf("attempt %d refused", i)
		}
		a.done("1.2.3.4", false)
	}
	if ok, wait := a.begin("1.2.3.4"); ok || wait != time.Minute {
		t.Fatalf("ok=%v wait=%v", ok, wait)
	}
	if ok, _ := a.begin("5.6.7.8"); !ok {
		t.Fatal("other IP blocked")
	}
	a.done("5.6.7.8", false)
	now = now.Add(time.Minute)
	if ok, _ := a.begin("1.2.3.4"); !ok {
		t.Fatal("still blocked after window")
	}
}

func TestCheckRunsScryptAlways(t *testing.T) {
	a, _ := newAuth("pw")
	// Both paths go through derive and a constant-time compare.
	if a.check("") || a.check("p") || a.check("pwx") || !a.check("pw") {
		t.Fatal("check mismatch")
	}
	if len(a.hash) != 32 || len(a.salt) != 16 {
		t.Fatal("hash/salt size")
	}
}

func TestClientsCRUD(t *testing.T) {
	e := newEnv(t)
	e.login()
	in := map[string]any{"name": "A", "enabled": true, "protocol": "vless", "address": "a.example",
		"port": 443, "uuid": u1, "network": "ws", "tls": "tls", "path": "/x", "id": "ignored"}
	var c clientView
	e.expect("POST", "/api/clients", in, 201, &c)
	if c.ID == "" || c.ID == "ignored" || c.Status.State != "up" || *c.Status.TCPMs != 12 || c.Traffic.Conns != 3 {
		t.Fatalf("create: %+v", c)
	}

	var list []clientView
	e.expect("GET", "/api/clients", nil, 200, &list)
	if len(list) != 1 || list[0].ID != c.ID {
		t.Fatalf("list: %+v", list)
	}

	in["name"] = "B"
	var got clientView
	e.expect("PUT", "/api/clients/"+c.ID, in, 200, &got)
	if got.ID != c.ID || got.Name != "B" {
		t.Fatalf("put: %+v", got)
	}
	e.expect("GET", "/api/clients/"+c.ID, nil, 200, &got)
	if got.Name != "B" {
		t.Fatal("not persisted")
	}

	e.expect("POST", "/api/clients/"+c.ID+"/toggle", nil, 200, &got)
	if got.Enabled || got.Status.State != "disabled" {
		t.Fatalf("toggle: %+v", got)
	}

	var l struct{ Link string }
	e.expect("GET", "/api/clients/"+c.ID+"/link", nil, 200, &l)
	if !strings.HasPrefix(l.Link, "vless://"+u1+"@a.example:443") {
		t.Fatalf("link %q", l.Link)
	}

	// Validation errors -> 400.
	bad := map[string]any{"name": "x", "protocol": "trojan", "address": "a", "port": 1, "uuid": u1}
	e.expect("POST", "/api/clients", bad, 400, nil)
	e.expect("PUT", "/api/clients/nope", in, 404, nil)

	// Put the client into a group and a rule, then delete it.
	e.expect("PUT", "/api/groups/default", map[string]any{"name": "Default", "strategy": "failover", "members": []string{c.ID}}, 200, nil)
	rules := []router.Rule{
		{Type: "domain", Values: []string{"x.com"}, Target: router.Target{Kind: "client", ID: c.ID}},
		{ID: "default", Type: "default", Target: router.Target{Kind: "group", ID: "default"}},
	}
	e.expect("PUT", "/api/rules", rules, 200, nil)
	e.expect("DELETE", "/api/clients/"+c.ID, nil, 204, nil)
	e.expect("DELETE", "/api/clients/"+c.ID, nil, 404, nil)
	cfg := e.store.Get()
	if len(cfg.Clients) != 0 || len(cfg.Groups[0].Members) != 0 || len(cfg.Rules) != 1 {
		t.Fatalf("refs left: %+v", cfg)
	}
}

func TestGroupsAndRules(t *testing.T) {
	e := newEnv(t)
	e.login()
	var g groupView
	e.expect("POST", "/api/groups", map[string]any{"name": "G", "strategy": "least-ping"}, 201, &g)
	if g.ID == "" || g.Current != "cur-"+g.ID || g.Members == nil {
		t.Fatalf("group: %+v", g)
	}
	e.expect("POST", "/api/groups", map[string]any{"name": "H", "strategy": "bogus"}, 400, nil)
	e.expect("POST", "/api/groups", map[string]any{"name": "H", "strategy": "failover", "members": []string{"nope"}}, 400, nil)

	var rules []router.Rule
	e.expect("PUT", "/api/rules", []router.Rule{
		{Type: "domain", Values: []string{"a.com"}, Target: router.Target{Kind: "group", ID: g.ID}},
		{ID: "default", Type: "default", Target: router.Target{Kind: "group", ID: "default"}},
	}, 200, &rules)
	if rules[0].ID == "" || rules[1].ID != "default" {
		t.Fatalf("rule ids: %+v", rules)
	}
	e.expect("PUT", "/api/rules", []router.Rule{{Type: "domain", Target: router.Target{Kind: "group", ID: "missing"}}}, 400, nil)

	e.expect("DELETE", "/api/groups/"+g.ID, nil, 409, nil)
	e.expect("PUT", "/api/rules", rules[1:], 200, nil)
	e.expect("DELETE", "/api/groups/"+g.ID, nil, 204, nil)
	e.expect("GET", "/api/groups/"+g.ID, nil, 404, nil)
}

func TestImport(t *testing.T) {
	e := newEnv(t)
	e.login()
	text := strings.Join([]string{
		link(t, "one", "a.example", 443, u1),
		"# comment",
		"ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss",
		"vless://broken",
		link(t, "two", "b.example", 8443, u2),
		link(t, "one again", "a.example", 443, u1),
	}, "\n")
	var res struct {
		Added   []clientView      `json:"added"`
		Errors  []share.LineError `json:"errors"`
		Skipped int               `json:"skipped"`
	}
	e.expect("POST", "/api/import", map[string]string{"text": text}, 200, &res)
	if len(res.Added) != 2 || len(res.Errors) != 1 || res.Errors[0].Line != 4 || res.Skipped != 2 {
		t.Fatalf("import: %+v", res)
	}
	if !res.Added[0].Enabled || res.Added[0].Network != "ws" || res.Added[0].Path != "/ws" {
		t.Fatalf("client: %+v", res.Added[0])
	}
	if m := e.store.Get().Group("default").Members; len(m) != 2 || m[0] != res.Added[0].ID {
		t.Fatalf("default members %v", m)
	}
}

func TestSubscriptionRefreshKeepsIDs(t *testing.T) {
	e := newEnv(t)
	e.login()
	const url = "https://sub.example/s"
	b64 := func(links ...string) string {
		return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	}
	e.setSub(url, b64(link(t, "one", "a.example", 443, u1), link(t, "two", "b.example", 443, u2)))

	var sub config.Subscription
	e.expect("POST", "/api/subscriptions", map[string]string{"name": "S", "url": url}, 201, &sub)
	if sub.Count != 2 || sub.LastError != "" || sub.LastUpdate == "" {
		t.Fatalf("sub: %+v", sub)
	}
	cfg := e.store.Get()
	var one, two string
	for _, c := range cfg.Clients {
		if c.SubscriptionID != sub.ID {
			t.Fatal("subscriptionId not set")
		}
		switch c.UUID {
		case u1:
			one = c.ID
		case u2:
			two = c.ID
		}
	}
	// Disable "one" and route to it; drop "two" from the feed, add "three".
	e.expect("POST", "/api/clients/"+one+"/toggle", nil, 200, nil)
	e.expect("PUT", "/api/rules", []router.Rule{
		{ID: "r", Type: "domain", Values: []string{"a.com"}, Target: router.Target{Kind: "client", ID: one}},
		{ID: "default", Type: "default", Target: router.Target{Kind: "group", ID: "default"}},
	}, 200, nil)
	e.setSub(url, b64(link(t, "one renamed", "a.example", 443, u1), link(t, "three", "c.example", 443, u3)))

	e.expect("POST", "/api/subscriptions/"+sub.ID+"/refresh", nil, 200, &sub)
	cfg = e.store.Get()
	if sub.Count != 2 || len(cfg.Clients) != 2 {
		t.Fatalf("after refresh: %+v %+v", sub, cfg.Clients)
	}
	c1 := cfg.Client(one)
	if c1 == nil || c1.Enabled || c1.Name != "one renamed" {
		t.Fatalf("one not preserved: %+v", c1)
	}
	if cfg.Client(two) != nil {
		t.Fatal("two not removed")
	}
	if len(cfg.Rules) != 2 || cfg.Rules[0].Target.ID != one {
		t.Fatalf("rules: %+v", cfg.Rules)
	}
	for _, m := range cfg.Group("default").Members {
		if m == two {
			t.Fatal("two still in default group")
		}
	}

	// A failed fetch keeps the clients and records the error.
	e.setSub(url, "")
	e.expect("POST", "/api/subscriptions/"+sub.ID+"/refresh", nil, 200, &sub)
	if sub.LastError == "" || len(e.store.Get().Clients) != 2 {
		t.Fatalf("failed refresh: %+v", sub)
	}

	e.expect("DELETE", "/api/subscriptions/"+sub.ID, nil, 204, nil)
	cfg = e.store.Get()
	if len(cfg.Clients) != 0 || len(cfg.Subscriptions) != 0 || len(cfg.Rules) != 1 {
		t.Fatalf("delete: %+v", cfg)
	}
	e.expect("POST", "/api/subscriptions", map[string]string{"url": "ftp://x"}, 400, nil)
}

func TestSettingsPasswordWriteOnly(t *testing.T) {
	e := newEnv(t)
	e.login()
	var raw map[string]any
	e.expect("GET", "/api/settings", nil, 200, &raw)
	ros := raw["routeros"].(map[string]any)
	if ros["password"] != "" || ros["passwordSet"] != false {
		t.Fatalf("initial: %v", ros)
	}
	ros["password"] = "rpw"
	e.expect("PUT", "/api/settings", raw, 200, &raw)
	ros = raw["routeros"].(map[string]any)
	if ros["password"] != "" || ros["passwordSet"] != true {
		t.Fatalf("after set: %v", ros)
	}
	if e.store.Get().Settings.RouterOS.Password != "rpw" {
		t.Fatal("not stored")
	}
	ros["password"] = ""
	ros["addressList"] = "nl"
	ros["certSha256"] = strings.Repeat("ab", 32)
	e.expect("PUT", "/api/settings", raw, 200, &raw)
	st := e.store.Get().Settings.RouterOS
	if st.Password != "rpw" || st.AddressList != "nl" || st.CertSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("kept: %+v", st)
	}
	e.expect("GET", "/api/settings", nil, 200, &raw)
	ros = raw["routeros"].(map[string]any)
	if ros["certSha256"] != strings.Repeat("ab", 32) {
		t.Fatalf("certSha256 not returned: %v", ros)
	}
	// Changing the URL (or user) without a new password drops the stored
	// one, so it is never sent to a server the admin did not enter it for.
	ros["url"] = "http://evil.example"
	e.expect("PUT", "/api/settings", raw, 200, &raw)
	if st := e.store.Get().Settings.RouterOS; st.Password != "" || raw["routeros"].(map[string]any)["passwordSet"] != false {
		t.Fatalf("password kept after url change: %+v", st)
	}
	ros = raw["routeros"].(map[string]any)
	ros["password"], ros["user"] = "p2", "u"
	e.expect("PUT", "/api/settings", raw, 200, &raw)
	ros = raw["routeros"].(map[string]any)
	ros["user"] = "u2"
	e.expect("PUT", "/api/settings", raw, 200, &raw)
	if st := e.store.Get().Settings.RouterOS; st.Password != "" || st.User != "u2" {
		t.Fatalf("password kept after user change: %+v", st)
	}
	raw["healthInterval"] = 1
	e.expect("PUT", "/api/settings", raw, 400, nil)
}

func TestStatsAndConnections(t *testing.T) {
	e := newEnv(t)
	e.login()
	var v map[string]string
	e.expect("GET", "/api/stats?target=group:default&range=24h", nil, 200, &v)
	if v["target"] != "group:default" || v["range"] != "24h" {
		t.Fatal(v)
	}
	e.expect("GET", "/api/stats", nil, 200, &v)
	if v["target"] != "total" || v["range"] != "1h" {
		t.Fatal(v)
	}
	e.expect("GET", "/api/stats?range=2d", nil, 400, nil)
	e.expect("GET", "/api/stats?target=client:nope", nil, 404, nil)
	e.expect("GET", "/api/stats?target=foo", nil, 400, nil)
	e.expect("GET", "/api/connections", nil, 200, nil)
	e.expect("GET", "/api/nope", nil, 404, nil)
}

func TestSSE(t *testing.T) {
	e := newEnv(t)
	e.login()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+"/api/events", nil)
	req.AddCookie(e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatal(ct)
	}
	br := bufio.NewReader(resp.Body)
	if l, _ := br.ReadString('\n'); l != "retry: 3000\n" {
		t.Fatalf("first line %q", l)
	}
	// The subscription exists once the first bytes arrived.
	e.bus.Publish(events.Event{Type: events.Group, Data: map[string]string{"id": "g", "current": "c"}})
	var got []string
	for len(got) < 2 {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "event:") || strings.HasPrefix(l, "data:") {
			got = append(got, l)
		}
	}
	if got[0] != "event: group" || got[1] != `data: {"current":"c","id":"g"}` {
		t.Fatalf("got %q", got)
	}
}
