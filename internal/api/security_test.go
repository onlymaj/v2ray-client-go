package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
