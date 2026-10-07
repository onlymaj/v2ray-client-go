package health

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/events"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// fakeProber dials the destination directly (no proxy).
type fakeProber struct {
	delay   time.Duration
	fail    atomic.Bool
	active  *atomic.Int32
	maxSeen *atomic.Int32
}

func (f *fakeProber) DialServer(ctx context.Context) (time.Duration, error) {
	if f.active != nil {
		n := f.active.Add(1)
		defer f.active.Add(-1)
		for {
			m := f.maxSeen.Load()
			if n <= m || f.maxSeen.CompareAndSwap(m, n) {
				break
			}
		}
	}
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	if f.fail.Load() {
		return 0, errors.New("connection refused")
	}
	return f.delay, nil
}

func (f *fakeProber) Dial(ctx context.Context, network string, dest outbound.Addr) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, dest.String())
}

func server(t *testing.T, code int) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/generate_204" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/generate_204"
}

func TestReadStatus(t *testing.T) {
	for in, want := range map[string]int{
		"HTTP/1.1 204 No Content\r\n": 204,
		"HTTP/1.0 200 OK\r\n":         200,
		"HTTP/1.1 200\r\n":            200,
	} {
		got, err := readStatus(bufio.NewReader(strings.NewReader(in)))
		if err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "SSH-2.0-OpenSSH\r\n", "HTTP/1.1 2x4 No\r\n", "HTTP/1.1 2045\r\n", strings.Repeat("x", 300)} {
		if _, err := readStatus(bufio.NewReaderSize(strings.NewReader(in), 256)); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}

func TestCheckHTTP(t *testing.T) {
	p := &fakeProber{delay: 5 * time.Millisecond}
	c := New(func(string) Prober { return p }, Options{URL: server(t, 204)})
	c.SetClients([]string{"a"})
	st := c.CheckNow(context.Background(), "a")
	if st.State != StateUp || st.TCPMs < 5 || st.DelayMs < 0 || st.LastSuccess.IsZero() || st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	if got := c.Status("a"); got != st {
		t.Fatalf("Status() = %+v", got)
	}

	c.SetURL(server(t, 500))
	st = c.CheckNow(context.Background(), "a")
	if st.State != StateDown || st.DelayMs != -1 || !strings.Contains(st.LastError, "500") {
		t.Fatalf("500: %+v", st)
	}
	if st.LastSuccess.IsZero() {
		t.Fatal("LastSuccess should survive a failure")
	}
}

func TestTransitionsAndEvents(t *testing.T) {
	bus := events.New()
	ch, cancel := bus.Subscribe()
	defer cancel()
	p := &fakeProber{}
	c := New(func(id string) Prober {
		if id == "a" {
			return p
		}
		return nil
	}, Options{URL: server(t, 200), Bus: bus})
	c.SetClients([]string{"a"})

	var mu sync.Mutex
	var order []string
	c.OnResult(func(id string, st Status) { mu.Lock(); order = append(order, "1:"+st.State); mu.Unlock() })
	c.OnResult(func(id string, st Status) { mu.Lock(); order = append(order, "2:"+st.State); mu.Unlock() })

	ctx := context.Background()
	c.CheckNow(ctx, "a") // unknown -> up
	c.CheckNow(ctx, "a") // up, no change
	p.fail.Store(true)
	c.CheckNow(ctx, "a") // up -> down

	want := []string{"1:up", "2:up", "1:up", "2:up", "1:down", "2:down"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("callbacks %v", order)
	}
	var got []string
	for len(ch) > 0 {
		e := <-ch
		js, _ := json.Marshal(e.Data)
		got = append(got, e.Type+string(js))
	}
	if len(got) != 5 ||
		!strings.HasPrefix(got[0], `ping{"id":"a","tcpMs":0,"delayMs":`) ||
		got[1] != `status{"id":"a","state":"up","lastError":""}` ||
		!strings.HasPrefix(got[2], "ping") ||
		got[3] != `ping{"id":"a","tcpMs":-1,"delayMs":-1,"state":"down"}` ||
		got[4] != `status{"id":"a","state":"down","lastError":"connection refused"}` {
		t.Fatalf("events:\n%s", strings.Join(got, "\n"))
	}

	if st := c.CheckNow(ctx, "zzz"); st.State != StateUnknown {
		t.Fatalf("unknown client: %+v", st)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var active, maxSeen atomic.Int32
	p := &fakeProber{delay: 30 * time.Millisecond, active: &active, maxSeen: &maxSeen}
	p.fail.Store(true) // stop after the TCP stage
	c := New(func(string) Prober { return p }, Options{})
	ids := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	c.SetClients(ids)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Go(func() { c.CheckNow(context.Background(), id) })
	}
	wg.Wait()
	if m := maxSeen.Load(); m != maxConcurrent {
		t.Fatalf("max concurrent = %d, want %d", m, maxConcurrent)
	}
}

func TestTimeout(t *testing.T) {
	p := &fakeProber{delay: time.Second}
	c := New(func(string) Prober { return p }, Options{Timeout: 20 * time.Millisecond})
	c.SetClients([]string{"a"})
	start := time.Now()
	st := c.CheckNow(context.Background(), "a")
	if st.State != StateDown || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("%+v after %v", st, time.Since(start))
	}
}

func TestRunSchedules(t *testing.T) {
	p := &fakeProber{}
	url := server(t, 204)
	var mu sync.Mutex
	counts := map[string]int{}
	c := New(func(string) Prober { return p }, Options{URL: url, Interval: 50 * time.Millisecond})
	c.OnResult(func(id string, st Status) { mu.Lock(); counts[id]++; mu.Unlock() })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	time.Sleep(20 * time.Millisecond)
	c.SetClients([]string{"new"}) // added after start: checked immediately and then every ~50ms
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	n := counts["new"]
	mu.Unlock()
	if n < 4 || n > 8 {
		t.Fatalf("checks in 300ms at 50ms interval = %d", n)
	}
	if c.Status("new").State != StateUp {
		t.Fatalf("status %+v", c.Status("new"))
	}
	c.SetClients(nil)
	if c.Status("new").State != StateUnknown {
		t.Fatal("removed client should be unknown")
	}
}

func TestParseURL(t *testing.T) {
	p, err := parseURL("https://www.gstatic.com/generate_204")
	if err != nil || !p.tls || p.dest.Domain != "www.gstatic.com" || p.dest.Port != 443 ||
		!strings.HasPrefix(string(p.req), "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n") {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = parseURL("http://1.2.3.4:8080/x?y=1")
	if err != nil || p.tls || p.dest.IP.String() != "1.2.3.4" || p.dest.Port != 8080 ||
		!strings.HasPrefix(string(p.req), "GET /x?y=1 HTTP/1.1\r\nHost: 1.2.3.4:8080\r\n") {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []string{"ftp://x/", "http:///x", "http://x:99999/"} {
		if _, err := parseURL(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
