package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/onlymaj/v2ray-client-go/internal/config"
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
	if len(e.rt.checked) != maxCheckNow {
		t.Fatalf("CheckNow called %d times", len(e.rt.checked))
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
