// Package health periodically checks each enabled client: TCP connect time
// to its server, then the "real delay" of a minimal HTTP GET through the
// proxy to a probe URL (default https://www.gstatic.com/generate_204).
package health

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/events"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"

	// Embedded CA roots, used by crypto/x509 when the container has no
	// system certificate store.
	_ "golang.org/x/crypto/x509roots/fallback"
)

const (
	DefaultURL      = "https://www.gstatic.com/generate_204"
	DefaultInterval = 60 * time.Second
	DefaultTimeout  = 10 * time.Second
	maxConcurrent   = 4 // per lane, see SetClients
	maxNow          = 2
	startSpread     = 5 * time.Second
)

const (
	StateUp      = "up"
	StateDown    = "down"
	StateUnknown = "unknown"
)

// Prober is what a check needs from a client's outbound.
type Prober interface {
	// DialServer opens (and closes) a TCP connection to the proxy server
	// and returns the connect time.
	DialServer(ctx context.Context) (time.Duration, error)
	Dial(ctx context.Context, network string, dest outbound.Addr) (net.Conn, error)
}

// Status is the latest check result for one client. TCPMs and DelayMs are
// -1 when that stage failed or did not run.
type Status struct {
	State       string    `json:"state"`
	TCPMs       int       `json:"tcpMs"`
	DelayMs     int       `json:"delayMs"`
	LastError   string    `json:"lastError,omitempty"`
	LastSuccess time.Time `json:"lastSuccess"`
	LastCheck   time.Time `json:"lastCheck"`
}

type Options struct {
	URL      string        // default DefaultURL
	Interval time.Duration // default DefaultInterval
	Timeout  time.Duration // per check, default DefaultTimeout
	Bus      *events.Bus   // optional; gets events.Ping and events.Status
}

type entry struct {
	st      Status
	next    time.Time // zero = schedule when Run starts
	running bool
	low     bool // untrusted: checked in its own lane
}

// Checker schedules and runs checks. Safe for concurrent use.
type Checker struct {
	lookup  func(clientID string) Prober
	bus     *events.Bus
	timeout time.Duration
	sem     chan struct{} // scheduled checks of the admin's own clients
	lowSem  chan struct{} // scheduled checks of untrusted clients
	nowSem  chan struct{} // CheckNow
	wake    chan struct{}

	mu       sync.Mutex
	interval time.Duration
	target   *probeURL
	clients  map[string]*entry
	started  bool
	onResult []func(id string, st Status)
}

// New returns a Checker; lookup returns nil for unknown clients.
func New(lookup func(clientID string) Prober, opts Options) *Checker {
	c := &Checker{
		lookup:   lookup,
		bus:      opts.Bus,
		timeout:  opts.Timeout,
		sem:      make(chan struct{}, maxConcurrent),
		lowSem:   make(chan struct{}, maxConcurrent),
		nowSem:   make(chan struct{}, maxNow),
		wake:     make(chan struct{}, 1),
		interval: DefaultInterval,
		clients:  map[string]*entry{},
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	c.SetInterval(opts.Interval)
	c.SetURL(opts.URL)
	return c
}

// OnResult registers a callback, called after every check in registration
// order, from the checking goroutine. Register before Run.
func (c *Checker) OnResult(f func(id string, st Status)) {
	c.mu.Lock()
	c.onResult = append(c.onResult, f)
	c.mu.Unlock()
}

// SetInterval changes the check period; <= 0 means the default. It takes
// effect from each client's next check.
func (c *Checker) SetInterval(d time.Duration) {
	if d <= 0 {
		d = DefaultInterval
	}
	c.mu.Lock()
	c.interval = d
	c.mu.Unlock()
}

// SetURL changes the probe URL; "" or an invalid URL means the default.
func (c *Checker) SetURL(u string) error {
	p, err := parseURL(u)
	if u == "" || err != nil {
		p, _ = parseURL(DefaultURL)
	}
	c.mu.Lock()
	c.target = p
	c.mu.Unlock()
	return err
}

// SetClients replaces the set of checked (enabled) clients. Clients new to
// the set are checked immediately once Run is running; removed clients lose
// their status.
//
// low (may be nil) reports the clients that came from a subscription or a
// pasted link. Their scheduled checks have their own concurrency limit:
// a subscription can add a thousand servers that accept and then stall,
// each holding a slot for the whole timeout, and the admin's own clients
// must not wait behind them (round 15).
func (c *Checker) SetClients(ids []string, low func(id string) bool) {
	c.mu.Lock()
	keep := make(map[string]bool, len(ids))
	for _, id := range ids {
		keep[id] = true
		e := c.clients[id]
		if e == nil {
			e = &entry{st: Status{State: StateUnknown, TCPMs: -1, DelayMs: -1}}
			if c.started {
				e.next = time.Now()
			}
			c.clients[id] = e
		}
		e.low = low != nil && low(id)
	}
	for id := range c.clients {
		if !keep[id] {
			delete(c.clients, id)
		}
	}
	c.mu.Unlock()
	c.poke()
}

// Status returns the latest status of a client; unknown clients report
// StateUnknown.
func (c *Checker) Status(id string) Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.clients[id]; e != nil {
		return e.st
	}
	return Status{State: StateUnknown, TCPMs: -1, DelayMs: -1}
}

func (c *Checker) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Run schedules checks until ctx is done. Clients known at start are
// spread over the first 5 seconds.
func (c *Checker) Run(ctx context.Context) {
	c.mu.Lock()
	c.started = true
	now := time.Now()
	for _, e := range c.clients {
		if e.next.IsZero() {
			e.next = now.Add(rand.N(startSpread))
		}
	}
	c.mu.Unlock()

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		now := time.Now()
		wait := time.Minute
		var due []string
		c.mu.Lock()
		for id, e := range c.clients {
			if e.running {
				continue
			}
			if !e.next.After(now) {
				e.running = true
				due = append(due, id)
			} else if d := e.next.Sub(now); d < wait {
				wait = d
			}
		}
		c.mu.Unlock()
		for _, id := range due {
			go c.run(ctx, id)
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-c.wake:
		}
	}
}

// CheckNow runs a check for id right away (subject to its own concurrency
// limit, so it does not wait behind the scheduled checks), waits for it and
// returns the new status. It reports StateUnknown
// for a client that lookup does not know.
func (c *Checker) CheckNow(ctx context.Context, id string) Status {
	return c.check(ctx, id, c.nowSem)
}

// run is a scheduled check; it reschedules the client when done.
func (c *Checker) run(ctx context.Context, id string) {
	sem := c.sem
	c.mu.Lock()
	if e := c.clients[id]; e != nil && e.low {
		sem = c.lowSem
	}
	c.mu.Unlock()
	c.check(ctx, id, sem)
	c.mu.Lock()
	if e := c.clients[id]; e != nil {
		e.running = false
		// ±10% jitter so clients drift apart.
		j := time.Duration((rand.Float64()*0.2 - 0.1) * float64(c.interval))
		e.next = time.Now().Add(c.interval + j)
	}
	c.mu.Unlock()
	c.poke()
}

func (c *Checker) check(ctx context.Context, id string, sem chan struct{}) Status {
	p := c.lookup(id)
	if p == nil {
		return c.Status(id)
	}
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return c.Status(id)
	}
	c.mu.Lock()
	target := c.target
	c.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	st := Status{State: StateUp, TCPMs: -1, DelayMs: -1, LastCheck: time.Now()}
	tcp, err := p.DialServer(cctx)
	if err == nil {
		st.TCPMs = ms(tcp)
		var delay time.Duration
		delay, err = probe(cctx, p, target)
		if err == nil {
			st.DelayMs = ms(delay)
			st.LastSuccess = st.LastCheck
		}
	}
	cancel()
	<-sem
	if err != nil {
		st.State = StateDown
		// The text can come from the server (a WebSocket status line, a
		// gRPC message) and is kept per client and sent to the UI.
		st.LastError = clip(err.Error(), maxLastError)
		if ctx.Err() != nil {
			return c.Status(id) // shutting down; don't record
		}
	}

	c.mu.Lock()
	e := c.clients[id]
	if e == nil { // removed meanwhile
		c.mu.Unlock()
		return st
	}
	prev := e.st.State
	if st.LastSuccess.IsZero() {
		st.LastSuccess = e.st.LastSuccess
	}
	e.st = st
	cbs := c.onResult
	c.mu.Unlock()

	for _, f := range cbs {
		f(id, st)
	}
	if c.bus != nil {
		c.bus.Publish(events.Event{Type: events.Ping, Data: pingEvent{id, st.TCPMs, st.DelayMs, st.State}})
		if st.State != prev {
			c.bus.Publish(events.Event{Type: events.Status, Data: statusEvent{id, st.State, st.LastError}})
		}
	}
	return st
}

type pingEvent struct {
	ID      string `json:"id"`
	TCPMs   int    `json:"tcpMs"`
	DelayMs int    `json:"delayMs"`
	State   string `json:"state"`
}

type statusEvent struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	LastError string `json:"lastError"`
}

// maxLastError bounds Status.LastError.
const maxLastError = 300

// clip cuts s to at most n bytes of valid UTF-8.
func clip(s string, n int) string {
	if len(s) <= n {
		return strings.ToValidUTF8(s, "")
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

func ms(d time.Duration) int {
	if d > 0 && d < time.Millisecond {
		return 1
	}
	return int(d / time.Millisecond)
}

// probeURL is a pre-parsed probe target.
type probeURL struct {
	tls  bool
	host string // for SNI and the Host header
	dest outbound.Addr
	req  []byte
}

func parseURL(raw string) (*probeURL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	p := &probeURL{host: u.Hostname()}
	port := 80
	switch u.Scheme {
	case "https":
		p.tls, port = true, 443
	case "http":
	default:
		return nil, fmt.Errorf("health: unsupported URL scheme %q", u.Scheme)
	}
	if p.host == "" {
		return nil, errors.New("health: URL has no host")
	}
	if s := u.Port(); s != "" {
		if port, err = strconv.Atoi(s); err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("health: bad port %q", s)
		}
	}
	p.dest.Port = uint16(port)
	if ip, err := netip.ParseAddr(p.host); err == nil {
		p.dest.IP = ip
	} else {
		p.dest.Domain = p.host
	}
	path := u.RequestURI()
	p.req = fmt.Appendf(nil, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, u.Host)
	return p, nil
}

// probe measures the time from opening the proxied connection until the
// response status line arrives.
func probe(ctx context.Context, p Prober, u *probeURL) (time.Duration, error) {
	start := time.Now()
	conn, err := p.Dial(ctx, "tcp", u.dest)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if u.tls {
		tc := tls.Client(conn, &tls.Config{ServerName: u.host})
		if err := tc.HandshakeContext(ctx); err != nil {
			return 0, err
		}
		conn = tc
	}
	if _, err := conn.Write(u.req); err != nil {
		return 0, err
	}
	code, err := readStatus(bufio.NewReaderSize(conn, 256))
	if err != nil {
		return 0, err
	}
	d := time.Since(start)
	if code != 200 && code != 204 {
		return 0, fmt.Errorf("health: unexpected HTTP status %d", code)
	}
	return d, nil
}

// readStatus parses an HTTP/1.x status line and returns the code.
func readStatus(r *bufio.Reader) (int, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return 0, errors.New("health: status line too long")
		}
		return 0, err
	}
	// "HTTP/1.1 204 No Content\r\n"
	if len(line) < 12 || string(line[:7]) != "HTTP/1." || line[8] != ' ' {
		return 0, fmt.Errorf("health: bad status line %q", line)
	}
	code, err := strconv.Atoi(string(line[9:12]))
	if err != nil || (len(line) > 12 && line[12] != ' ' && line[12] != '\r' && line[12] != '\n') {
		return 0, fmt.Errorf("health: bad status line %q", line)
	}
	return code, nil
}
