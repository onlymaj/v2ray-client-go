// Command v2ray-client-go is the v2ray-client-go: a VLESS/VMess client for
// RouterOS containers with a web UI. It installs a REDIRECT for incoming TCP,
// routes every connection by the configured rules through a client, a group,
// directly or nowhere, and serves the API and UI from the same binary.
//
// Environment:
//
//	ADMIN_PASSWORD  required; UI/API login password
//	CONFIG_DIR      directory holding config.json (default /data)
//	ROS_URL, ROS_USER, ROS_PASS  override the RouterOS API settings. When
//	                ROS_PASS is set, the URL must come from ROS_URL too, so a UI
//	                user can't redirect the env password to another host.
//	UI_HOSTS        extra host names allowed in the Host header of API
//	                requests (IP literals are always allowed); DNS rebinding guard
//	NO_REDIRECT=1   don't install the netfilter REDIRECT (development)
//
// Port changes in settings take effect after a restart.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/api"
	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/dispatch"
	"github.com/onlymaj/v2ray-client-go/internal/dns"
	"github.com/onlymaj/v2ray-client-go/internal/events"
	"github.com/onlymaj/v2ray-client-go/internal/health"
	"github.com/onlymaj/v2ray-client-go/internal/inbound"
	"github.com/onlymaj/v2ray-client-go/internal/netfilter"
	"github.com/onlymaj/v2ray-client-go/internal/netguard"
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/routeros"
	"github.com/onlymaj/v2ray-client-go/internal/stats"
	"github.com/onlymaj/v2ray-client-go/internal/web"
	"golang.org/x/net/netutil"
)

func main() {
	log.SetFlags(log.LstdFlags)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dir := envOr("CONFIG_DIR", "/data")
	store, err := config.Open(filepath.Join(dir, "config.json"))
	if err != nil {
		return err
	}
	cfg := store.Get()

	bus := events.New()
	st := stats.New(bus)
	d, err := dispatch.New(cfg, tracker{st})
	if err != nil {
		log.Printf("config: %v", err) // the rest of the config still applies
	}
	defer d.Close()
	d.OnGroupChange(func(groupID, current string) {
		bus.Publish(events.Event{Type: events.Group, Data: map[string]string{"id": groupID, "current": current}})
	})

	checker := health.New(func(id string) health.Prober {
		if c := d.Client(id); c != nil {
			return prober{c}
		}
		return nil
	}, health.Options{Bus: bus})
	checker.OnResult(func(id string, s health.Status) {
		up := s.State == health.StateUp
		ms := float64(s.DelayMs)
		if !up {
			ms = -1
		}
		st.RecordDelay(id, ms)
		d.HealthUpdate(id, up, time.Duration(s.DelayMs)*time.Millisecond)
	})

	dnsSrv := dns.New(dns.Options{
		Upstream: cfg.Settings.DNSUpstream,
		// Route by the query name, but connect to the upstream itself. The
		// returned key is that of the route actually taken, so the server
		// won't pool or cache under a key whose route changed meanwhile.
		DialKeyed: func(ctx context.Context, src netip.Addr, qname string, dst outbound.Addr) (net.Conn, string, error) {
			c, dec, err := d.DialRouted(ctx, src, qname, dst)
			return c, dnsRouteKey(dec), err
		},
		RouteKey: func(src netip.Addr, qname string, dst netip.Addr) string {
			return dnsRouteKey(d.Route(src, qname, dst))
		},
		// Under DNS Option B the router forwards every LAN query, so they all
		// arrive from the gateway: give it (and the container itself) a much
		// higher per-source budget than a single LAN device.
		SourceLimit: func(src netip.Addr) (int, int) {
			// Exact gateway/own addresses only: Refused would also match
			// ranges such as 169.254.0.0/16 that any LAN device can use.
			if netguard.Self(src) {
				return 256, -1 // no UDP rate limit; docs drop forged 172.17.0.0/24 sources
			}
			return 0, 0 // defaults
		},
		Logf: log.Printf,
	})

	ros := routeros.New(routeros.Options{Logf: log.Printf})

	// apply pushes a config snapshot into every component. It runs once at
	// startup and after every successful Store.Update.
	// Store.Update calls subscribers after releasing its lock, so two
	// overlapping saves can deliver snapshots out of order. Serialize applies
	// and always apply the store's latest snapshot, so a stale one arriving
	// last can't leave the running state behind what the UI shows (e.g. the
	// kill switch still "direct" after it was set to "block").
	var applyMu sync.Mutex
	prev := cfg
	apply := func(*config.Config) {
		applyMu.Lock()
		defer applyMu.Unlock()
		c := store.Get()
		if err := d.Update(c); err != nil {
			log.Printf("config: %v", err)
		}
		// Every enabled client's server goes into the RouterOS no-proxy list
		// (spec). docs/routeros.md only uses that list for router-originated
		// traffic, never to exempt LAN traffic, so a subscription can't make
		// LAN traffic to arbitrary IPs skip the proxy.
		var enabled, servers []string
		for _, cl := range c.Clients {
			if cl.Enabled {
				enabled = append(enabled, cl.ID)
				servers = append(servers, cl.Address)
			}
		}
		checker.SetClients(enabled)
		checker.SetInterval(time.Duration(c.Settings.HealthInterval) * time.Second)
		if err := checker.SetURL(c.Settings.HealthURL); err != nil {
			log.Printf("health url: %v", err)
		}
		dnsSrv.SetUpstream(c.Settings.DNSUpstream)
		dnsSrv.Flush()
		r := c.Settings.RouterOS
		rosURL, rosEnabled := envOr("ROS_URL", r.URL), r.Enabled || os.Getenv("ROS_URL") != ""
		if os.Getenv("ROS_PASS") != "" && os.Getenv("ROS_URL") == "" {
			// Never send an env-supplied password to a URL set through the UI.
			rosEnabled = false
			log.Print("routeros: ROS_PASS is set but ROS_URL is not; sync disabled")
		}
		ros.SetConfig(rosEnabled, rosURL, envOr("ROS_USER", r.User), envOr("ROS_PASS", r.Password), r.AddressList, r.CertSHA256)
		ros.SetServers(servers)

		for _, old := range prev.Clients {
			if c.Client(old.ID) == nil {
				st.Forget("client:" + old.ID)
			}
		}
		for _, old := range prev.Groups {
			if c.Group(old.ID) == nil {
				st.Forget("group:" + old.ID)
			}
		}
		prev = c
	}
	apply(cfg)
	store.OnChange(apply)

	if os.Getenv("NO_REDIRECT") != "1" {
		inst, err := netfilter.Install(netfilter.Redirect{Port: cfg.Settings.Ports.Transparent, ExcludeDst: netfilter.LocalAddrs()})
		if err != nil {
			return fmt.Errorf("netfilter: %w", err)
		}
		log.Printf("redirect installed via %s -> :%d", inst.Method, cfg.Settings.Ports.Transparent)
		defer inst.Remove()
	}

	ui, err := api.New(api.Options{
		Store:         store,
		Bus:           bus,
		Runtime:       runtime{ctx: ctx, st: st, hc: checker, d: d},
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
		AllowedHosts:  splitList(os.Getenv("UI_HOSTS")),
		Web:           web.Handler(),
	})
	if err != nil {
		return err
	}
	os.Unsetenv("ADMIN_PASSWORD")

	p := cfg.Settings.Ports
	errc := make(chan error, 6)
	serve := func(name string, port uint16, f func(context.Context, net.Listener, inbound.Handler) error) error {
		if port == 0 {
			return nil
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		log.Printf("%s listening on :%d", name, port)
		go func() { errc <- f(ctx, ln, d) }()
		return nil
	}
	if err := serve("transparent", p.Transparent, inbound.ServeTransparent); err != nil {
		return err
	}
	if err := serve("socks5", p.SOCKS, inbound.ServeSOCKS); err != nil {
		return err
	}
	if err := serve("http-connect", p.HTTP, inbound.ServeHTTP); err != nil {
		return err
	}
	if p.DNS != 0 {
		go func() { errc <- dnsSrv.ListenAndServe(ctx, ":"+strconv.Itoa(int(p.DNS))) }()
	}

	// ReadTimeout bounds slow-body uploads; the SSE handler clears its own
	// deadlines.
	hs := &http.Server{
		Handler:           ui,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	uiLn, err := net.Listen("tcp", ":"+strconv.Itoa(int(p.UI)))
	if err != nil {
		return fmt.Errorf("ui: %w", err)
	}
	// The UI is reachable without auth up to the login page; cap
	// connections so idle keep-alives from one LAN host can't exhaust memory.
	uiLn = &capListener{Listener: netutil.LimitListener(uiLn, uiMaxConns), perIP: map[netip.Addr]int{}}
	go func() {
		log.Printf("ui listening on :%d", p.UI)
		if err := hs.Serve(uiLn); !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("ui: %w", err)
		}
	}()

	go st.Run(ctx)
	go checker.Run(ctx)
	go ros.Run(ctx)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil {
			stop()
			return err
		}
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hs.Shutdown(shutCtx)
	log.Print("stopped")
	return nil
}

// splitList parses a comma-separated env value, dropping empty items.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// dnsRouteKey identifies a DNS route for the forwarder's cache and
// connection pool. Group routes are keyed by group, not by the member Pick
// chose: every member may carry that traffic, and keying by member would
// split the cache and let a round-robin key differ from the member Dial
// uses. Kind is included, so a kill-switch "direct" decision never shares a
// key with the proxied route.
func dnsRouteKey(r dispatch.Decision) string {
	target := r.ClientID
	if r.GroupID != "" {
		target = "g:" + r.GroupID
	}
	return r.RuleID + "|" + r.Kind + "|" + target
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// tracker adapts *stats.Stats to dispatch.Tracker (the Open return types
// differ by package).
type tracker struct{ s *stats.Stats }

func (t tracker) Open(src netip.AddrPort, dst, domain, ruleID, clientID, groupID string) dispatch.Tracked {
	return t.s.Open(src, dst, domain, ruleID, clientID, groupID)
}

// prober uses Probe (bypasses the warm pool) so health checks don't count as
// traffic.
type prober struct {
	c interface {
		DialServer(context.Context) (time.Duration, error)
		Probe(context.Context, string, outbound.Addr) (net.Conn, error)
	}
}

func (p prober) DialServer(ctx context.Context) (time.Duration, error) { return p.c.DialServer(ctx) }
func (p prober) Dial(ctx context.Context, network string, dest outbound.Addr) (net.Conn, error) {
	return p.c.Probe(ctx, network, dest)
}

// runtime adapts stats, health and the dispatcher to api.Runtime.
type runtime struct {
	ctx context.Context
	st  *stats.Stats
	hc  *health.Checker
	d   *dispatch.Dispatcher
}

func (r runtime) ClientStatus(id string) api.Status {
	s := r.hc.Status(id)
	return api.Status{
		State: s.State, TCPMs: max(s.TCPMs, 0), DelayMs: max(s.DelayMs, 0),
		LastError: s.LastError, LastSuccess: s.LastSuccess, LastCheck: s.LastCheck,
	}
}

func (r runtime) Traffic(target string) api.Traffic {
	t := r.st.Traffic(target)
	return api.Traffic{
		Up: uint64(t.Up), Down: uint64(t.Down),
		UpRate: uint64(t.UpRate), DownRate: uint64(t.DownRate), Conns: int(t.Conns),
	}
}

func (r runtime) GroupCurrent(id string) string          { return r.d.GroupCurrent(id) }
func (r runtime) Series(target, rng string) (any, error) { return r.st.Series(target, rng) }
func (r runtime) Connections() any                       { return r.st.Connections() }
func (r runtime) CheckNow(id string)                     { go r.hc.CheckNow(r.ctx, id) }

const (
	uiMaxConns      = 64 // all UI/API connections
	uiMaxConnsPerIP = 16
)

// capListener closes connections from a source (an IPv4 address or an IPv6
// /64) that already holds uiMaxConnsPerIP open UI connections.
type capListener struct {
	net.Listener
	mu    sync.Mutex
	perIP map[netip.Addr]int
}

func (l *capListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil {
			return c, nil
		}
		ip := ap.Addr().Unmap()
		if ip.Is6() {
			// One host can hold many IPv6 addresses; count its /64.
			ip = netip.PrefixFrom(ip, 64).Masked().Addr()
		}
		l.mu.Lock()
		if l.perIP[ip] >= uiMaxConnsPerIP {
			l.mu.Unlock()
			c.Close()
			continue
		}
		l.perIP[ip]++
		l.mu.Unlock()
		return &capConn{Conn: c, release: func() {
			l.mu.Lock()
			if l.perIP[ip]--; l.perIP[ip] <= 0 {
				delete(l.perIP, ip)
			}
			l.mu.Unlock()
		}}, nil
	}
}

type capConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *capConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
