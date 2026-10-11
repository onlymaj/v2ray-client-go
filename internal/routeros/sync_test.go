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
	got, err := s.resolveAll(context.Background(), []string{"many.example", "198.51.100.7"}, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxAddrsPerHost+1 || len(cache["many.example"]) != maxAddrsPerHost {
		t.Fatalf("kept %d addresses (%d cached), want %d per host", len(got), len(cache["many.example"]), maxAddrsPerHost)
	}
}
