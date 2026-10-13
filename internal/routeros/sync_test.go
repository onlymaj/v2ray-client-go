package routeros

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeROS is a stateful stand-in for /rest/ip/firewall/address-list.
type fakeROS struct {
	mu      sync.Mutex
	nextID  int
	entries []Entry
	fail    atomic.Bool
	gets    atomic.Int32
	writes  atomic.Int32
	srv     *httptest.Server
}

func newFakeROS(t *testing.T, initial ...Entry) *fakeROS {
	f := &fakeROS{nextID: 1}
	for _, e := range initial {
		f.add(e)
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeROS) add(e Entry) {
	e.ID = fmt.Sprintf("*%X", f.nextID)
	f.nextID++
	f.entries = append(f.entries, e)
}

func (f *fakeROS) serve(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "secret" {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(apiError{Error: 401, Message: "Unauthorized"})
		return
	}
	if f.fail.Load() {
		f.gets.Add(1)
		w.WriteHeader(500)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const prefix = "/rest/ip/firewall/address-list"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == prefix:
		f.gets.Add(1)
		list := r.URL.Query().Get("list")
		out := []Entry{}
		for _, e := range f.entries {
			if list == "" || e.List == list {
				out = append(out, e)
			}
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPut && r.URL.Path == prefix:
		f.writes.Add(1)
		var e Entry
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil || e.List == "" || e.Address == "" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(apiError{Error: 400, Message: "Bad Request", Detail: "missing field"})
			return
		}
		for _, x := range f.entries {
			if x.List == e.List && normAddr(x.Address) == normAddr(e.Address) {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(apiError{Error: 400, Message: "Bad Request", Detail: "failure: already have such entry"})
				return
			}
		}
		f.add(e)
		json.NewEncoder(w).Encode(f.entries[len(f.entries)-1])
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, prefix+"/"):
		f.writes.Add(1)
		id := strings.TrimPrefix(r.URL.Path, prefix+"/")
		for i, e := range f.entries {
			if e.ID == id {
				f.entries = slices.Delete(f.entries, i, i+1)
				w.WriteHeader(204)
				return
			}
		}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(apiError{Error: 404, Message: "Not Found", Detail: "no such item"})
	default:
		w.WriteHeader(400)
	}
}

// snapshot returns "list address comment" lines, sorted.
func (f *fakeROS) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.entries {
		out = append(out, e.List+" "+normAddr(e.Address)+" "+e.Comment)
	}
	slices.Sort(out)
	return out
}

type fakeResolver struct {
	mu   sync.Mutex
	m    map[string][]string
	errs map[string]bool
}

func (r *fakeResolver) set(host string, ips ...string) {
	r.mu.Lock()
	r.m[host] = ips
	r.mu.Unlock()
}

func (r *fakeResolver) resolve(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errs[host] {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, s := range r.m[host] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func equalLines(got []string, want ...string) bool {
	slices.Sort(want)
	return slices.Equal(got, want)
}

func TestSyncAddRemoveOwnership(t *testing.T) {
	f := newFakeROS(t,
		Entry{List: "no-proxy", Address: "192.168.88.0/24", Comment: "lan"},
		Entry{List: "no-proxy", Address: "9.9.9.9", Comment: "user"},
		Entry{List: "no-proxy", Address: "7.7.7.7/32", Comment: OwnerComment}, // stale, ours
		Entry{List: "other", Address: "7.7.7.7", Comment: OwnerComment},       // other list: untouched
	)
	res := &fakeResolver{m: map[string][]string{"srv.example": {"5.5.5.5", "6.6.6.6", "2001:db8::1"}}}
	s := New(Options{Resolve: res.resolve, HTTPClient: f.srv.Client(), MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	s.SetConfig(true, f.srv.URL+"/", "admin", "secret", "no-proxy", "")
	s.SetServers([]string{"srv.example", "9.9.9.9", "1.2.3.4", "2001:db8::2", "1.2.3.4"})

	waitFor(t, "initial sync", func() bool {
		return equalLines(f.snapshot(),
			"no-proxy 192.168.88.0/24 lan",
			"no-proxy 9.9.9.9 user", // already present: not duplicated
			"no-proxy 1.2.3.4 "+OwnerComment,
			"no-proxy 5.5.5.5 "+OwnerComment,
			"no-proxy 6.6.6.6 "+OwnerComment,
			"other 7.7.7.7 "+OwnerComment)
	})
	waitFor(t, "status", func() bool { st := s.Status(); return st.Entries == 3 && st.LastError == "" && !st.LastSync.IsZero() })

	// No change: no API writes on re-trigger.
	w := f.writes.Load()
	s.SetServers([]string{"srv.example", "9.9.9.9", "1.2.3.4"})
	time.Sleep(50 * time.Millisecond)
	if f.writes.Load() != w {
		t.Fatalf("writes without a change: %d -> %d", w, f.writes.Load())
	}

	// DNS change and a removed server.
	res.set("srv.example", "5.5.5.5", "8.8.4.4")
	s.SetServers([]string{"srv.example"})
	waitFor(t, "resync after change", func() bool {
		return equalLines(f.snapshot(),
			"no-proxy 192.168.88.0/24 lan",
			"no-proxy 9.9.9.9 user",
			"no-proxy 5.5.5.5 "+OwnerComment,
			"no-proxy 8.8.4.4 "+OwnerComment,
			"other 7.7.7.7 "+OwnerComment)
	})

	// Resolve failure keeps the last good addresses and reports the error.
	res.mu.Lock()
	res.errs = map[string]bool{"srv.example": true}
	res.mu.Unlock()
	s.SetServers([]string{"srv.example"})
	waitFor(t, "resolve error", func() bool { return strings.Contains(s.Status().LastError, "srv.example") })
	if !slices.Contains(f.snapshot(), "no-proxy 5.5.5.5 "+OwnerComment) {
		t.Fatal("entries removed on resolve failure")
	}

	// Removing all servers removes all owned entries only.
	res.mu.Lock()
	res.errs = nil
	res.mu.Unlock()
	s.SetServers(nil)
	waitFor(t, "cleanup", func() bool {
		return equalLines(f.snapshot(), "no-proxy 192.168.88.0/24 lan", "no-proxy 9.9.9.9 user", "other 7.7.7.7 "+OwnerComment)
	})
}

func TestSyncBackoff(t *testing.T) {
	f := newFakeROS(t)
	f.fail.Store(true)
	s := New(Options{HTTPClient: f.srv.Client(), MinBackoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond})
	if got := []time.Duration{s.backoff(1), s.backoff(2), s.backoff(3), s.backoff(4), s.backoff(10)}; !slices.Equal(got, []time.Duration{20e6, 40e6, 80e6, 80e6, 80e6}) {
		t.Fatalf("backoff %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	s.SetServers([]string{"1.1.1.1"})
	s.SetConfig(true, f.srv.URL, "admin", "secret", "no-proxy", "")
	time.Sleep(500 * time.Millisecond)
	// 20+40+80+80+80+80+80 ms: about 7 attempts in 500 ms; hammering would be hundreds.
	if n := f.gets.Load(); n < 3 || n > 12 {
		t.Fatalf("attempts in 500ms: %d", n)
	}
	if st := s.Status(); st.LastError == "" || !st.LastSync.IsZero() {
		t.Fatalf("status %+v", st)
	}

	f.fail.Store(false)
	waitFor(t, "recovery", func() bool { st := s.Status(); return st.LastError == "" && st.Entries == 1 })

	// Disabled: no further calls.
	s.SetConfig(false, f.srv.URL, "admin", "secret", "no-proxy", "")
	time.Sleep(20 * time.Millisecond)
	n := f.gets.Load()
	time.Sleep(200 * time.Millisecond)
	if f.gets.Load() != n {
		t.Fatal("API called while disabled")
	}
}

func TestClientErrors(t *testing.T) {
	f := newFakeROS(t)
	c := newClient(f.srv.URL+"/rest", "admin", "wrong", f.srv.Client())
	_, err := c.List(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err %v", err)
	}
	c = newClient(f.srv.URL, "admin", "secret", f.srv.Client())
	if err := c.Remove(context.Background(), "*99"); err == nil || !strings.Contains(err.Error(), "no such item") {
		t.Fatalf("err %v", err)
	}
	// Self-signed cert: NewClient with insecure=true works, false fails.
	if _, err := NewClient(f.srv.URL, "admin", "secret", true, "").List(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(f.srv.URL, "admin", "secret", false, "").List(context.Background(), "x"); err == nil {
		t.Fatal("verified a self-signed cert")
	}
}

func TestClientCertPin(t *testing.T) {
	f := newFakeROS(t)
	sum := sha256.Sum256(f.srv.Certificate().Raw)
	good := hex.EncodeToString(sum[:])
	var colons []string
	for _, b := range sum {
		colons = append(colons, fmt.Sprintf("%02X", b))
	}
	for _, pin := range []string{good, strings.ToUpper(good), strings.Join(colons, ":")} {
		if _, err := NewClient(f.srv.URL, "admin", "secret", false, pin).List(context.Background(), "x"); err != nil {
			t.Fatalf("pin %q: %v", pin, err)
		}
	}
	bad := sum
	bad[0] ^= 1
	for _, pin := range []string{hex.EncodeToString(bad[:]), "zz", good[:10]} {
		// insecure=true must not override a pin; a malformed pin fails closed.
		if _, err := NewClient(f.srv.URL, "admin", "secret", true, pin).List(context.Background(), "x"); err == nil {
			t.Fatalf("pin %q accepted", pin)
		}
	}
}

func TestSyncWarnsWithoutPin(t *testing.T) {
	f := newFakeROS(t)
	var mu sync.Mutex
	var logs []string
	logf := func(format string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	s := New(Options{Logf: logf})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	s.SetConfig(true, f.srv.URL, "admin", "secret", "no-proxy", "")
	waitFor(t, "sync", func() bool { return !s.Status().LastSync.IsZero() })
	s.SetConfig(true, f.srv.URL, "admin", "secret", "other", "") // new client, no second warning
	sum := sha256.Sum256(f.srv.Certificate().Raw)
	s.SetConfig(true, f.srv.URL, "admin", "secret", "no-proxy", hex.EncodeToString(sum[:]))
	waitFor(t, "pinned sync", func() bool { st := s.Status(); return st.LastError == "" && !st.LastSync.IsZero() })
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	n := 0
	for _, l := range logs {
		if strings.Contains(l, "certSha256 is not set") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("warnings %d, logs %q", n, logs)
	}
}

// Round 8: a host name from a subscription could resolve to thousands of
// addresses, each sent to the router as a firewall address-list entry.
func TestResolveAllBounds(t *testing.T) {
	s := New(Options{Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
		out := make([]netip.Addr, 500)
		for i := range out {
			out[i] = netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)})
		}
		return out, nil
	}})
	cache := map[string][]netip.Addr{}
	got, _, err := s.resolveAll(context.Background(), []string{"many.example", "198.51.100.7"}, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxAddrsPerHost+1 || len(cache["many.example"]) != maxAddrsPerHost {
		t.Fatalf("kept %d addresses (%d cached), want %d per host", len(got), len(cache["many.example"]), maxAddrsPerHost)
	}
}

// Round 9: with the pass deadline from round 8, names at the end of the
// list were skipped on every pass when the ones before them were slow.
// Names never resolved go first, and the rest rotate.
func TestResolveAllOrder(t *testing.T) {
	var order []string
	s := New(Options{Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
		order = append(order, host)
		return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
	}})
	cache := map[string][]netip.Addr{}
	hosts := []string{"a", "b", "c"}
	s.resolveAll(context.Background(), hosts, cache)
	first := map[string]bool{}
	for range 3 {
		order = nil
		s.resolveAll(context.Background(), append(hosts, "new"), cache)
		if order[0] != "new" {
			t.Fatalf("unresolved name not first: %v", order)
		}
		delete(cache, "new")
		first[order[1]] = true
	}
	if len(first) != 3 {
		t.Fatalf("resolved names do not rotate: %v", first)
	}
}

// Round 9: (a) one name that never resolves (common in subscription lists)
// kept the sync in add-only mode for ever, so stale entries stayed on the
// router; (b) the address cap was filled in resolve order, which rotates,
// so the admin's own server could drop out of the list and entries churned.
func TestResolveAllHoldAndStableCap(t *testing.T) {
	s := New(Options{Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "dead.example" {
			return nil, errors.New("no such host")
		}
		var n int
		fmt.Sscanf(host, "h%d", &n)
		out := make([]netip.Addr, maxAddrsPerHost)
		for i := range out {
			out[i] = netip.AddrFrom4([4]byte{203, byte(n >> 8), byte(n), byte(i)})
		}
		return out, nil
	}})
	cache := map[string][]netip.Addr{}
	if _, hold, err := s.resolveAll(context.Background(), []string{"dead.example"}, cache); !hold || err == nil {
		t.Fatal("a name that has not resolved yet must hold back removals")
	}
	s.firstFail["dead.example"] = time.Now().Add(-unresolvedHold - time.Minute)
	if _, hold, err := s.resolveAll(context.Background(), []string{"dead.example"}, cache); hold || err == nil {
		t.Fatalf("dead name after the hold: hold=%v err=%v, want the error reported without a hold", hold, err)
	}

	hosts := []string{"198.51.100.7"} // the admin's server, first in the config
	for i := range 400 {
		hosts = append(hosts, fmt.Sprintf("h%d.example", i))
	}
	var first []string
	for pass := range 4 {
		got, _, err := s.resolveAll(context.Background(), hosts, cache)
		if err != nil || len(got) != maxAddrs || !slices.Contains(got, "198.51.100.7") {
			t.Fatalf("pass %d: %d addresses, err %v, admin server kept: %v", pass, len(got), err, slices.Contains(got, "198.51.100.7"))
		}
		if pass == 0 {
			first = got
		} else if !slices.Equal(first, got) {
			t.Fatalf("pass %d: capped set changed", pass)
		}
	}
}

// Round 10: names that never resolve were put first on every pass. A dozen
// that are slow to fail used up the whole pass, so no name that had resolved
// before was ever refreshed again.
func TestResolveAllDeadNamesDoNotStarve(t *testing.T) {
	defer func(d time.Duration) { maxResolvePass = d }(maxResolvePass)
	maxResolvePass = 200 * time.Millisecond
	fresh := netip.MustParseAddr("203.0.113.9")
	s := New(Options{Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host != "good.example" {
			<-ctx.Done() // slow to fail
			return nil, ctx.Err()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return []netip.Addr{fresh}, nil
	}})
	cache := map[string][]netip.Addr{"good.example": {netip.MustParseAddr("203.0.113.1")}}
	var hosts []string
	s.firstFail = map[string]time.Time{}
	for i := range 12 {
		h := fmt.Sprintf("dead%d.example", i)
		hosts = append(hosts, h)
		s.firstFail[h] = time.Now()
	}
	hosts = append(hosts, "good.example")
	s.resolveAll(context.Background(), hosts, cache)
	if got := cache["good.example"]; len(got) != 1 || got[0] != fresh {
		t.Fatalf("known name not refreshed behind dead names: %v", got)
	}
}

// Round 16: every failed write kept the router's whole reply (up to 4 MB,
// with its newlines) and all of them were joined into one log message on
// every retry; 300 refused addresses made a 600 KB, 600-line log entry.
func TestSyncErrorsAreShortAndOneLine(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte("[]"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"error": 403, "message": "Forbidden", "detail": strings.Repeat("not allowed\n", 200)})
	}))
	defer srv.Close()
	var desired []string
	for i := range 300 {
		desired = append(desired, fmt.Sprintf("203.0.%d.%d", i/250, i%250+1))
	}
	s := New(Options{Logf: func(string, ...any) {}})
	_, err := s.reconcile(context.Background(), newClient(srv.URL+"/rest", "u", "p", srv.Client()), "no-proxy", desired, true)
	if err == nil {
		t.Fatal("no error from 300 refused writes")
	}
	if msg := err.Error(); len(msg) > 2000 || strings.ContainsAny(msg, "\r\n") || !strings.Contains(msg, "297 more") {
		t.Fatalf("error is %d bytes: %.300q", len(msg), msg)
	}
}

// Round 18: a 1 MiB reply of "[{},{},...]" was decoded into 350,000
// entries, 33 MiB, kept for the whole pass.
func TestListStopsAtEntryLimit(t *testing.T) {
	n := maxListed + 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[" + strings.Repeat("{},", n-1) + "{}]"))
	}))
	defer srv.Close()
	c := newClient(srv.URL, "u", "p", srv.Client())
	if _, err := c.List(context.Background(), "no-proxy"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("list of %d entries: %v", n, err)
	}
	n = 3
	if got, err := c.List(context.Background(), "no-proxy"); err != nil || len(got) != 0 {
		t.Fatalf("short list: %v %v", got, err)
	}
}

// Round 18: the client followed redirects, so an answerer without a pinned
// certificate could send the app's requests, and on the same host its
// password, anywhere the container reaches.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("[]")) }))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "u", "p", true, "")
	if _, err := c.List(context.Background(), "no-proxy"); err == nil {
		t.Fatal("redirected reply accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

// Round 18: a router that stopped answering after the list was read got
// every write of the pass, 10 s each, for up to 2048 addresses.
func TestReconcileEndsWhenRouterStopsAnswering(t *testing.T) {
	var writes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte("[]"))
			return
		}
		writes.Add(1)
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close() // no reply
	}))
	defer srv.Close()
	var desired []string
	for i := range 200 {
		desired = append(desired, fmt.Sprintf("203.0.113.%d", i+1))
	}
	s := New(Options{Logf: func(string, ...any) {}})
	_, err := s.reconcile(context.Background(), newClient(srv.URL, "u", "p", srv.Client()), "no-proxy", desired, true)
	if err == nil || !strings.Contains(err.Error(), "pass ended early") {
		t.Fatalf("err %v", err)
	}
	// The HTTP client may retry a request on a closed connection.
	if n := writes.Load(); n > 4*maxLost {
		t.Fatalf("%d writes sent to a router that does not answer", n)
	}
}

// Round 19: only a failed connection counted as "no answer". A router that
// sent its reply headers and then nothing kept the pass going, one client
// timeout per address.
func TestReconcileEndsWhenRepliesStall(t *testing.T) {
	var writes atomic.Int32
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte("[]"))
			return
		}
		writes.Add(1)
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-stop
	}))
	defer srv.Close()
	defer close(stop)
	hc := srv.Client()
	hc.Timeout = 100 * time.Millisecond
	var desired []string
	for i := range 50 {
		desired = append(desired, fmt.Sprintf("203.0.113.%d", i+1))
	}
	s := New(Options{Logf: func(string, ...any) {}})
	_, err := s.reconcile(context.Background(), newClient(srv.URL, "u", "p", hc), "no-proxy", desired, true)
	if err == nil || !strings.Contains(err.Error(), "pass ended early") || writes.Load() > maxLost {
		t.Fatalf("%d writes, err %v", writes.Load(), err)
	}
}

// Round 19: every config save sets the server list, and that counted as a
// settings change which ended a running pass as failed.
func TestSavingTheConfigDoesNotEndAPass(t *testing.T) {
	var s *Syncer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte("[]"))
			return
		}
		s.SetServers([]string{"203.0.113.1"}) // a save during the pass
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	s = New(Options{Logf: func(string, ...any) {}})
	n, err := s.reconcile(context.Background(), newClient(srv.URL, "u", "p", srv.Client()), "no-proxy", []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, true)
	if err != nil || n != 3 {
		t.Fatalf("owned %d, err %v", n, err)
	}
}

// Round 19: reply headers were limited only by net/http's default of
// 10 MB, and 2.6 million header lines were 42 MiB while the reply was held.
func TestReplyHeadersAreBounded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := range 4 * maxReplyHeader / 16 {
			w.Header().Set(fmt.Sprintf("X-Pad-%07d", i), "v")
		}
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "u", "p", true, "")
	if _, err := c.List(context.Background(), "no-proxy"); err == nil {
		t.Fatal("a reply with 64 KiB of headers was accepted")
	}
}
