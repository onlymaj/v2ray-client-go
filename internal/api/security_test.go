package api

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/router"
	"github.com/onlymaj/v2ray-client-go/internal/share"
)

// Parallel logins from one IP must not get more guesses than loginAttempts.
func TestLoginParallelCannotBypassLimit(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", e.srv.URL+"/api/login", strings.NewReader(`{"password":"bad"}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			mu.Lock()
			codes[resp.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[401] > loginAttempts || codes[401]+codes[429] != 40 {
		t.Fatalf("codes %v", codes)
	}
}

func TestLoginInflightAndGlobalCap(t *testing.T) {
	a, _ := newAuth("pw")
	now := time.Unix(1000, 0)
	a.now = func() time.Time { return now }

	if ok, _ := a.begin("10.0.0.1"); !ok {
		t.Fatal("first refused")
	}
	if ok, _ := a.begin("10.0.0.1"); ok {
		t.Fatal("second in-flight login allowed")
	}
	a.done("10.0.0.1", true) // the admin logs in: trusted, count reset

	for i := 0; i < globalAttempts-1; i++ {
		ip := fmt.Sprintf("fd00::%x", i+1)
		if ok, _ := a.begin(ip); !ok {
			t.Fatalf("attempt %d refused", i)
		}
		a.done(ip, false)
	}
	if ok, wait := a.begin("fd00::ffff"); ok || wait <= 0 || wait > loginWindow {
		t.Fatalf("global cap: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := a.begin("10.0.0.1"); !ok {
		t.Fatal("trusted admin IP blocked by the global cap")
	}
	a.done("10.0.0.1", true)
	now = now.Add(loginWindow)
	if ok, _ := a.begin("fd00::ffff"); !ok {
		t.Fatal("still blocked after window")
	}
}

func TestLimiterMapBounded(t *testing.T) {
	a, _ := newAuth("pw")
	now := time.Unix(1000, 0)
	a.now = func() time.Time { return now }
	for i := 0; i < 20000; i++ {
		ip := fmt.Sprintf("fd00::%x", i)
		if ok, _ := a.begin(ip); ok {
			a.done(ip, false)
		}
		now = now.Add(100 * time.Millisecond)
	}
	if n := len(a.limits); n > 4*globalAttempts+1 {
		t.Fatalf("limiter map has %d entries", n)
	}
}

func TestLoginBodyLimit(t *testing.T) {
	e := newEnv(t)
	e.expect("POST", "/api/login", map[string]string{"password": strings.Repeat("x", 2000)}, 400, nil)
}

func manyLinks(t *testing.T, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(link(t, "n", fmt.Sprintf("h%d.example", i), 443, u1) + "\n")
	}
	return b.String()
}

func TestImportCaps(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.expect("POST", "/api/import", map[string]string{"text": manyLinks(t, share.MaxLinks+1)}, 400, nil)
	if n := len(e.store.Get().Clients); n != 0 {
		t.Fatalf("%d clients after refused import", n)
	}
	e.expect("POST", "/api/import", map[string]string{"text": manyLinks(t, 60)}, 200, nil)
	e.rt.mu.Lock()
	defer e.rt.mu.Unlock()
	// Round 16: imported clients are left to the health checker's own
	// lane for untrusted clients; they must not fill the CheckNow lane.
	if len(e.rt.checked) != 0 {
		t.Fatalf("CheckNow called %d times for imported clients", len(e.rt.checked))
	}
}

func TestSubscriptionCap(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.setSub("http://sub.example/big", manyLinks(t, share.MaxLinks+1))
	var sub config.Subscription
	e.expect("POST", "/api/subscriptions", map[string]string{"url": "http://sub.example/big"}, 201, &sub)
	if !strings.Contains(sub.LastError, "too many links") || sub.Count != 0 || len(e.store.Get().Clients) != 0 {
		t.Fatalf("sub %+v", sub)
	}
}

// Round 18: a subscription within the link limit that does not fit beside
// the clients already there was answered 400 after it had been saved, and
// showed neither an error nor a date.
func TestSubscriptionOverClientLimitIsRecorded(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.expect("POST", "/api/import", map[string]string{"text": manyLinks(t, 600)}, 200, nil)
	var b strings.Builder
	for i := range 600 {
		b.WriteString(link(t, "n", fmt.Sprintf("s%d.example", i), 443, u1) + "\n")
	}
	e.setSub("http://sub.example/more", b.String())
	var sub config.Subscription
	e.expect("POST", "/api/subscriptions", map[string]string{"url": "http://sub.example/more"}, 201, &sub)
	if !strings.Contains(sub.LastError, "too many clients") || sub.LastUpdate == "" || sub.Count != 0 {
		t.Fatalf("sub %+v", sub)
	}
	if cfg := e.store.Get(); len(cfg.Clients) != 600 || len(cfg.Subscriptions) != 1 || cfg.Subscriptions[0].LastError == "" {
		t.Fatalf("%d clients, subscriptions %+v", len(cfg.Clients), cfg.Subscriptions)
	}
}

func newHandler(t *testing.T, hosts ...string) http.Handler {
	st, _ := config.Open(filepath.Join(t.TempDir(), "c.json"))
	h, err := New(Options{Store: st, AdminPassword: "pw", AllowedHosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHostCheck(t *testing.T) {
	h := newHandler(t, "Router.LAN")
	for host, want := range map[string]int{
		"192.168.88.2":        401,
		"192.168.88.2:80":     401,
		"[fe80::1]:8080":      401,
		"localhost:80":        401,
		"router.lan":          401,
		"ROUTER.lan.:80":      401,
		"evil.example":        403,
		"192.168.88.2.nip.io": 403,
		"":                    403,
	} {
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("host %q: got %d want %d", host, w.Code, want)
		}
	}
}

func TestOriginCheck(t *testing.T) {
	h := newHandler(t)
	for origin, want := range map[string]int{
		"":                         204,
		"http://192.168.88.2":      204,
		"http://evil.example":      403,
		"http://192.168.88.2:8080": 403,
		"null":                     403,
	} {
		r := httptest.NewRequest("POST", "/api/logout", nil)
		r.Host = "192.168.88.2"
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("origin %q: got %d want %d", origin, w.Code, want)
		}
	}
}

func TestBlockedAddr(t *testing.T) {
	for s, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "172.17.0.1": true, "192.168.88.1": true,
		"100.64.0.1": true, "169.254.1.1": true, "0.0.0.0": true, "0.1.2.3": true,
		"::1": true, "fd00::1": true, "fe80::1": true, "::": true, "::ffff:127.0.0.1": true,
		"64:ff9b::a00:1": true, "224.0.0.1": true,
		"::1%lo": true, "64:ff9b::a00:1%eth0": true, // round 10: a zone must not hide the address
		"1.1.1.1": false, "8.8.8.8": false, "2606:4700::1111": false, "64:ff9b::808:808": false,
	} {
		if got := blockedAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: got %v want %v", s, got, want)
		}
	}
}

func TestFetchRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	}))
	defer other.Close()
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, srvURL+"/body", http.StatusFound)
		case "/body":
			w.Write([]byte("ok"))
		case "/away":
			http.Redirect(w, r, otherURL+"/", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, srvURL+"/loop", http.StatusFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL
	ctx := context.Background()

	// The URL itself may be on the LAN, and so may redirects to its host.
	if b, err := defaultFetch(ctx, srv.URL+"/same"); err != nil || string(b) != "ok" {
		t.Fatalf("same host: %q %v", b, err)
	}
	if _, err := defaultFetch(ctx, srv.URL+"/away"); !errors.Is(err, errRedirectBlocked) {
		t.Fatalf("redirect to loopback name: %v", err)
	}
	if _, err := defaultFetch(ctx, srv.URL+"/loop"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("loop: %v", err)
	}
	// The dial hook enforces the check on its own (e.g. if the redirect
	// target's DNS changes between CheckRedirect and the dial).
	_, err := fetchClient("sub.example").Get(other.URL)
	if !errors.Is(err, errRedirectBlocked) {
		t.Fatalf("dial hook: %v", err)
	}
}

// A same-host redirect to another port opens a new connection; it must go
// to the address pinned on the first dial even though the host's DNS answer
// changed in between (rebinding).
func TestFetchPinnedAcrossConns(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("lan"))
	}))
	defer target.Close()
	_, tport, _ := strings.Cut(strings.TrimPrefix(target.URL, "http://"), ":")
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://sub.example:"+tport+"/", http.StatusFound)
	}))
	defer start.Close()
	_, sport, _ := strings.Cut(strings.TrimPrefix(start.URL, "http://"), ":")

	var mu sync.Mutex
	answers := []string{"127.0.0.1", "192.0.2.1"} // second: rebound elsewhere
	n := 0
	old := fetchLookup
	fetchLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		a := answers[min(n, len(answers)-1)]
		n++
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	defer func() { fetchLookup = old }()
	b, err := defaultFetch(context.Background(), "http://sub.example:"+sport+"/")
	if err != nil || string(b) != "lan" || n != 1 {
		t.Fatalf("got %q %v after %d lookups; want the pinned 127.0.0.1 and 1 lookup", b, err, n)
	}
}

// A redirect to another name that resolves to a local address is refused
// at dial time even when CheckRedirect saw a public answer.
func TestFetchOtherHostRebind(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	}))
	defer other.Close()
	_, oport, _ := strings.Cut(strings.TrimPrefix(other.URL, "http://"), ":")
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.example:"+oport+"/", http.StatusFound)
	}))
	defer start.Close()
	var mu sync.Mutex
	evil := 0
	old := fetchLookup
	fetchLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		if host == "evil.example" {
			if evil++; evil == 1 {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	defer func() { fetchLookup = old }()
	_, sport, _ := strings.Cut(strings.TrimPrefix(start.URL, "http://"), ":")
	if _, err := defaultFetch(context.Background(), "http://start.example:"+sport+"/"); !errors.Is(err, errRedirectBlocked) {
		t.Fatalf("rebound redirect target: %v", err)
	}
}

func TestAPISecurityHeaders(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.do("GET", "/api/me", nil)
	for k, v := range map[string]string{
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func sessionReq(tok, remote string) *http.Request {
	r := httptest.NewRequest("GET", "/api/me", nil)
	r.RemoteAddr = remote
	r.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	return r
}

func TestSessionBoundToIP(t *testing.T) {
	a, err := newAuth("pw")
	if err != nil {
		t.Fatal(err)
	}
	tok := a.newSession("192.168.88.10")
	if !a.valid(sessionReq(tok, "192.168.88.10:5000")) {
		t.Fatal("same IP refused")
	}
	if a.valid(sessionReq(tok, "192.168.88.11:5000")) {
		t.Fatal("other IP accepted")
	}
	if !a.valid(sessionReq(tok, "192.168.88.10:6000")) {
		t.Fatal("a foreign attempt must not revoke the owner's session")
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	a, err := newAuth("pw")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)
	a.now = func() time.Time { return now }
	const ip = "10.0.0.5:1"
	tok := a.newSession("10.0.0.5")
	// Activity every 11 h keeps it alive...
	for i := 0; i < 5; i++ {
		now = now.Add(11 * time.Hour)
		if !a.valid(sessionReq(tok, ip)) {
			t.Fatalf("active session expired after %d steps", i+1)
		}
	}
	// ...12 h of silence ends it.
	now = now.Add(sessionIdle)
	if a.valid(sessionReq(tok, ip)) {
		t.Fatal("idle session accepted")
	}
	// The 7-day cap holds even with constant activity.
	tok = a.newSession("10.0.0.5")
	for elapsed := time.Duration(0); elapsed < sessionTTL-time.Hour; elapsed += time.Hour {
		now = now.Add(time.Hour)
		if !a.valid(sessionReq(tok, ip)) {
			t.Fatalf("active session expired at %v", elapsed)
		}
	}
	now = now.Add(2 * time.Hour)
	if a.valid(sessionReq(tok, ip)) {
		t.Fatal("session outlived sessionTTL")
	}
}

// Round 8: a subscription server's status line (megabytes of it) was stored
// as the subscription's lastError and written to config.json on every save.
func TestFetchErrorIsClipped(t *testing.T) {
	// Through the refresh itself (round 17: the test only called clip, so
	// removing the call in refresh failed nothing).
	e := newEnv(t)
	e.login()
	e.setSub("http://sub.example/err", "ERR:"+strings.Repeat("x", 5000))
	var sub config.Subscription
	e.expect("POST", "/api/subscriptions", map[string]string{"url": "http://sub.example/err"}, 201, &sub)
	if n := len(sub.LastError); n == 0 || n > maxLastError+3 {
		t.Fatalf("stored lastError is %d bytes, limit %d", n, maxLastError)
	}
	if got := e.store.Get().Subscriptions[0].LastError; len(got) > maxLastError+3 {
		t.Fatalf("saved lastError is %d bytes", len(got))
	}
	if got := clip(strings.Repeat("x", 5000), maxLastError); len(got) > maxLastError+3 {
		t.Fatalf("clip kept %d bytes", len(got))
	}
	if got := clip("caf\xc3", 10); got != "caf" {
		t.Fatalf("clip kept invalid UTF-8: %q", got)
	}
	if got := clip(strings.Repeat("é", 200), 301); !utf8.ValidString(got) {
		t.Fatal("clip cut a rune in half")
	}
}

// Round 9: every address of the subscription host was pinned and exempt
// from the public-address check. With two addresses, a same-host redirect
// to a port closed on the first fell through to the second: a request with
// a path the server chose, sent to an address it listed (the router, say).
func TestFetchPinsOneAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 not available:", err)
	}
	hit := make(chan string, 1)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- r.URL.String()
	}))
	target.Listener = ln
	target.Start()
	defer target.Close()
	_, tport, _ := net.SplitHostPort(ln.Addr().String())
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://sub.example:"+tport+"/cgi-bin/reboot?now=1", http.StatusFound)
	}))
	defer start.Close()
	_, sport, _ := net.SplitHostPort(start.Listener.Addr().String())

	old := fetchLookup
	defer func() { fetchLookup = old }()
	fetchLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}, nil
	}
	if _, err := defaultFetch(context.Background(), "http://sub.example:"+sport+"/"); err == nil {
		t.Error("redirect to the host's second address succeeded")
	}
	select {
	case u := <-hit:
		t.Fatalf("second address received %s", u)
	default:
	}

	// A name answering with public and private addresses is refused outright.
	fetchLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := defaultFetch(context.Background(), "http://sub.example:"+sport+"/"); !errors.Is(err, errRedirectBlocked) {
		t.Fatalf("mixed public/private answer: err = %v", err)
	}
}

// Round 10: a client no dialer can be built for (a uuid that is not a UUID,
// fp=ios, a bad Reality key) was saved with 200/201 and then never worked;
// the reason went only to the container log. Save and import now refuse it.
func TestUnusableClientRefused(t *testing.T) {
	e := newEnv(t)
	e.check = func(c config.Client) error {
		if c.Fingerprint == "ios" {
			return errors.New("tls: unknown fingerprint ios")
		}
		return nil
	}
	e.login()
	body := map[string]any{"name": "x", "protocol": "vless", "address": "a.example", "port": 443,
		"uuid": u1, "network": "tcp", "tls": "tls", "fingerprint": "ios"}
	e.expect("POST", "/api/clients", body, 400, nil)
	body["fingerprint"], body["name"] = "chrome", " "
	e.expect("POST", "/api/clients", body, 400, nil)
	body["name"] = "x"
	e.expect("POST", "/api/clients", body, 201, nil)

	var res struct {
		Added  []clientView      `json:"added"`
		Errors []share.LineError `json:"errors"`
	}
	text := "vless://" + u2 + "@b.example:443?security=tls&fp=ios#bad\n" + link(t, "good", "c.example", 443, u3)
	e.expect("POST", "/api/import", map[string]string{"text": text}, 200, &res)
	if len(res.Added) != 1 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Err, "fingerprint") {
		t.Fatalf("import: %+v", res)
	}
}

// Round 10: the API document, the UI and the mock all said a pasted base64
// subscription body is decoded; the server counted it as one skipped line.
func TestImportBase64Body(t *testing.T) {
	e := newEnv(t)
	e.login()
	text := base64.StdEncoding.EncodeToString([]byte(link(t, "one", "a.example", 443, u1) + "\n" + link(t, "two", "b.example", 443, u2)))
	var res struct {
		Added []clientView `json:"added"`
	}
	e.expect("POST", "/api/import", map[string]string{"text": text}, 200, &res)
	if len(res.Added) != 2 {
		t.Fatalf("base64 body: %d clients added, want 2", len(res.Added))
	}
}

// Round 10: when a client left a subscription (the provider only has to
// change its uuid or path), the refresh deleted the rules pointing at it and
// that traffic followed the later rules, e.g. default → direct. A client a
// rule points at now stays until the admin deletes it.
func TestRefreshKeepsClientARuleUses(t *testing.T) {
	e := newEnv(t)
	e.login()
	const url = "https://sub.example/s"
	e.setSub(url, link(t, "one", "a.example", 443, u1)+"\n"+link(t, "two", "b.example", 443, u2))
	var sub config.Subscription
	e.expect("POST", "/api/subscriptions", map[string]string{"name": "S", "url": url}, 201, &sub)
	var one, two string
	for _, c := range e.store.Get().Clients {
		if c.UUID == u1 {
			one = c.ID
		} else {
			two = c.ID
		}
	}
	e.expect("PUT", "/api/rules", []router.Rule{
		{ID: "r", Type: "source", Values: []string{"192.168.88.50"}, Target: router.Target{Kind: "client", ID: one}},
		{ID: "default", Type: "default", Target: router.Target{Kind: "direct"}},
	}, 200, nil)
	e.setSub(url, link(t, "one moved", "a.example", 443, u3))
	e.expect("POST", "/api/subscriptions/"+sub.ID+"/refresh", nil, 200, &sub)
	cfg := e.store.Get()
	if len(cfg.Rules) != 2 || cfg.Rules[0].Target.ID != one || cfg.Client(one) == nil {
		t.Fatalf("rule or its client removed by the refresh: %+v", cfg.Rules)
	}
	if cfg.Client(two) != nil {
		t.Fatal("a client no rule uses was kept")
	}
	if sub.Count != 2 || sub.LastError != "" || !strings.Contains(sub.Note, "kept because rules use them") {
		t.Fatalf("subscription does not report the kept client: %+v", sub)
	}
}

// Round 11: the check for more than share.MaxLinks links looked only at the
// last parse error. Round 10 added errors for unusable links after it, so one
// such link got an oversized list accepted and cut to the first links.
func TestTooManyLinksWithUnusableLink(t *testing.T) {
	e := newEnv(t)
	e.check = func(c config.Client) error {
		if c.Fingerprint == "ios" {
			return errors.New("tls: unknown fingerprint ios")
		}
		return nil
	}
	e.login()
	lines := []string{"vless://" + u1 + "@bad.example:443?security=tls&fp=ios#bad"}
	for i := range share.MaxLinks + 5 {
		lines = append(lines, link(t, "n", fmt.Sprintf("h%d.example", i), 443, u2))
	}
	e.expect("POST", "/api/import", map[string]string{"text": strings.Join(lines, "\n")}, 400, nil)
	if n := len(e.store.Get().Clients); n != 0 {
		t.Fatalf("%d clients saved from an oversized list", n)
	}
}

// Round 12: a rule with no values (the UI's "Add rule" with an empty box)
// was saved with 200 and matched nothing, so a block or direct rule the
// admin believed in did not exist. web/API.md and the mock already said 400.
func TestRuleWithoutValuesRefused(t *testing.T) {
	e := newEnv(t)
	e.login()
	def := router.Rule{ID: "default", Type: "default", Target: router.Target{Kind: "group", ID: "default"}}
	for _, vals := range [][]string{nil, {}, {" ", ""}} {
		e.expect("PUT", "/api/rules", []router.Rule{
			{Type: "dest", Values: vals, Target: router.Target{Kind: "block"}}, def}, 400, nil)
	}
	e.expect("PUT", "/api/rules", []router.Rule{
		{Type: "dest", Values: []string{"203.0.113.0/24"}, Target: router.Target{Kind: "block"}}, def}, 200, nil)
}

// Round 13: the example password from docs/routeros.md was accepted, and
// password guessing left no line in the log. The example is refused at
// start, and failed logins are logged with the source, a few per minute.
func TestExamplePasswordRefusedAndFailedLoginsLogged(t *testing.T) {
	if _, err := newAuth(docPassword); err == nil {
		t.Fatal("the documentation's example password was accepted")
	}
	e := newEnv(t)
	var mu sync.Mutex
	var lines []string
	old := logf
	logf = func(f string, a ...any) { mu.Lock(); lines = append(lines, fmt.Sprintf(f, a...)); mu.Unlock() }
	defer func() { logf = old }()
	loginLog.Lock()
	loginLog.start, loginLog.n, loginLog.more = time.Time{}, 0, 0
	loginLog.Unlock()

	e.expect("POST", "/api/login", map[string]string{"password": "guess-one"}, 401, nil)
	for range 20 {
		logLogin("failed login", "192.0.2.9")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != loginLogBurst || !strings.Contains(lines[0], "failed login from 127.0.0.1") {
		t.Fatalf("log lines: %q", lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "guess-one") {
			t.Fatal("the submitted password was logged")
		}
	}
}

// Round 15: the subscription body was capped but response headers were
// not (10 MB by default, on every redirect hop).
func TestFetchRefusesLargeHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Fill", strings.Repeat("x", 1<<20))
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	if b, err := defaultFetch(context.Background(), srv.URL); err == nil {
		t.Fatalf("fetch with 1 MiB of response headers succeeded (%d bytes)", len(b))
	}
}

// Round 17: a login request that announced a body and never sent it waited
// for the server's 30 s read timeout with its parsed headers in memory,
// about 280 KB per connection before any password. It is answered at once
// when the length is missing or too large, and after loginReadTimeout
// otherwise.
func TestLoginDoesNotWaitForBody(t *testing.T) {
	old := loginReadTimeout
	loginReadTimeout = 200 * time.Millisecond
	defer func() { loginReadTimeout = old }()
	e := newEnv(t)
	for name, head := range map[string]string{
		"body never sent": "Content-Length: 30\r\n",
		"chunked":         "Transfer-Encoding: chunked\r\n",
		"too long":        "Content-Length: 100000\r\n",
	} {
		c, err := net.Dial("tcp", e.srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "POST /api/login HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n%s\r\n", e.srv.Listener.Addr(), head)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 400") {
			t.Errorf("%s: %q %v, want a 400 within the read timeout", name, line, err)
		}
	}
}

// Round 18: the round-17 guard was in the login only. Every other refusal
// without a session (401, 403, 415, 404) left the announced body unread, and
// net/http waited for it until the server's read timeout before replying.
func TestRefusalsDoNotWaitForBody(t *testing.T) {
	e := newEnv(t)
	addr := e.srv.Listener.Addr().String()
	for name, tc := range map[string]struct{ req, want string }{
		"no session":      {"POST /api/clients HTTP/1.1\r\nHost: " + addr + "\r\nContent-Type: application/json\r\n", "401"},
		"content type":    {"POST /api/login HTTP/1.1\r\nHost: " + addr + "\r\nContent-Type: text/plain\r\n", "415"},
		"cross origin":    {"POST /api/login HTTP/1.1\r\nHost: " + addr + "\r\nOrigin: http://evil.example\r\nContent-Type: application/json\r\n", "403"},
		"unknown path":    {"POST /api/nothing HTTP/1.1\r\nHost: " + addr + "\r\nContent-Type: application/json\r\n", "40"},
		"ui path":         {"POST / HTTP/1.1\r\nHost: " + addr + "\r\n", ""},
		"get with a body": {"GET /api/clients HTTP/1.1\r\nHost: " + addr + "\r\n", "401"},
	} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "%sContent-Length: 30\r\n\r\n", tc.req)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 "+tc.want) {
			t.Errorf("%s: %q %v, want %s at once", name, line, err, tc.want)
		}
		// Round 19: and the server lets go of the connection, with the
		// request it holds, soon after; it waited for the body here too.
		if _, err := io.Copy(io.Discard, br); err != nil {
			t.Errorf("%s: connection still open 3 s after the refusal: %v", name, err)
		}
		c.Close()
	}
	// A login that does send its body keeps its connection.
	resp, _ := e.do("POST", "/api/login", map[string]string{"password": "s3cret"})
	if resp.StatusCode != 204 || resp.Close {
		t.Fatalf("login: status %d close %v", resp.StatusCode, resp.Close)
	}
}

// Round 17: a few megabytes of "[{},{},...]" were decoded into over a
// million rules before the count was checked. Only the link import takes a
// large body.
func TestJSONBodyCap(t *testing.T) {
	e := newEnv(t)
	e.login()
	big := json.RawMessage("[" + strings.Repeat("{},", maxJSONBody/3) + "{}]")
	e.expect("PUT", "/api/rules", big, 413, nil)
	// Round 18: the line above was refused for its rule count with or
	// without the cap. This body is valid apart from its size.
	vals := make([]string, maxJSONBody/16+1)
	for i := range vals {
		vals[i] = fmt.Sprintf("h%09d.example", i)
	}
	e.expect("PUT", "/api/rules", []router.Rule{{Type: "domain", Values: vals, Target: router.Target{Kind: "direct"}}}, 413, nil)
	e.expect("PUT", "/api/rules", []router.Rule{{Type: "domain", Values: vals[:100], Target: router.Target{Kind: "direct"}}}, 200, nil)
	e.expect("POST", "/api/import", map[string]string{"text": strings.Repeat("# not a link\n", maxJSONBody/10)}, 200, nil)
}

// Round 17: links without a name were stored with an empty one and showed
// as blank rows and blank options in the rule and group selects.
func TestImportedClientGetsAName(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.expect("POST", "/api/import", map[string]string{"text": strings.TrimSuffix(link(t, "", "noname.example", 443, u1), "#")}, 200, nil)
	cs := e.store.Get().Clients
	if len(cs) != 1 || cs[0].Name != "noname.example" {
		t.Fatalf("clients %+v", cs)
	}
}

// Round 19: a refresh waited without limit for the ones before it, and
// after the server's write timeout its reply could not be sent.
func TestRefreshDoesNotWaitForEver(t *testing.T) {
	old := subWait
	subWait = 100 * time.Millisecond
	defer func() { subWait = old }()
	e := newEnv(t)
	e.login()
	e.setSub("http://sub.example/a", manyLinks(t, 1))
	var sub config.Subscription
	e.expect("POST", "/api/subscriptions", map[string]string{"url": "http://sub.example/a"}, 201, &sub)
	e.h.subSem <- struct{}{} // another refresh is fetching
	e.expect("POST", "/api/subscriptions/"+sub.ID+"/refresh", nil, 200, &sub)
	<-e.h.subSem
	if !strings.Contains(sub.LastError, "still being fetched") {
		t.Fatalf("sub %+v", sub)
	}
	id := sub.ID
	sub = config.Subscription{}
	e.expect("POST", "/api/subscriptions/"+id+"/refresh", nil, 200, &sub)
	if sub.LastError != "" || sub.Count != 1 {
		t.Fatalf("sub after the wait %+v", sub)
	}
}

type deadlineSpy struct {
	http.ResponseWriter
	mu        sync.Mutex
	deadlines []time.Time
	writes    int
}

func (d *deadlineSpy) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadlines = append(d.deadlines, t)
	d.mu.Unlock()
	return nil
}
func (d *deadlineSpy) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Every write but the stream's opening line has a deadline.
	if d.writes++; d.writes > 1 && d.deadlines[len(d.deadlines)-1].IsZero() {
		panic("event written without a write deadline")
	}
	return d.ResponseWriter.Write(p)
}
func (d *deadlineSpy) Flush() {}

// Round 19: the event stream cleared its write deadline for good, so a
// client that stopped reading held the handler in a write, its queued
// events, and the stream past a logout.
func TestSSEWritesHaveADeadline(t *testing.T) {
	old := heartbeat
	heartbeat = 20 * time.Millisecond
	defer func() { heartbeat = old }()
	e := newEnv(t)
	e.login()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/api/events", nil).WithContext(ctx)
	req.AddCookie(e.cookie)
	req.RemoteAddr = "127.0.0.1:1"
	spy := &deadlineSpy{ResponseWriter: httptest.NewRecorder()}
	done := make(chan struct{})
	go func() { e.h.events(spy, req); close(done) }()
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
	spy.mu.Lock()
	defer spy.mu.Unlock()
	if spy.writes < 2 {
		t.Fatalf("%d writes, want the opening line and heartbeats", spy.writes)
	}
}

// Round 19: a link import could be 4 MiB and was held in several copies.
func TestImportBodyCap(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.expect("POST", "/api/import", map[string]string{"text": strings.Repeat("# not a link\n", maxBody/13+1)}, 413, nil)
}

// Round 20: a subscription host whose name resolves only to the container,
// its gateway, loopback or a link-local address was fetched like one the
// admin hosts on the LAN. The gateway is the router, whose REST service
// trusts requests from the container.
func TestFetchRefusesSelfAndGateway(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("router"))
	}))
	defer srv.Close()
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	oldL, oldR := fetchLookup, fetchRefused
	fetchLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	fetchRefused = func(ip netip.Addr) bool { return ip.IsLoopback() } // as netguard.Refused does
	defer func() { fetchLookup, fetchRefused = oldL, oldR }()
	if _, err := defaultFetch(context.Background(), "http://sub.example:"+port+"/"); !errors.Is(err, errFetchRefused) || hits.Load() != 0 {
		t.Fatalf("err %v, %d requests reached the server", err, hits.Load())
	}
}
