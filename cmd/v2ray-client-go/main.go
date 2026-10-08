// Command v2ray-client-go is the v2ray-client-go: a VLESS/VMess client for
// RouterOS containers with a web UI. It installs a REDIRECT for incoming TCP,
// routes every connection by the configured rules through a client, a group,
// directly or nowhere, and serves the API and UI from the same binary.
//
// Environment:
//
//	ADMIN_PASSWORD  required; UI/API login password
//	CONFIG_DIR      directory holding config.json (default /data)
//	ROS_URL, ROS_USER, ROS_PASS  override the RouterOS API settings
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
	"github.com/onlymaj/v2ray-client-go/internal/outbound"
	"github.com/onlymaj/v2ray-client-go/internal/routeros"
	"github.com/onlymaj/v2ray-client-go/internal/stats"
	"github.com/onlymaj/v2ray-client-go/internal/web"
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
		Dial: func(ctx context.Context, src netip.Addr, qname string, dst outbound.Addr) (net.Conn, error) {
			c, _, err := d.Dial(ctx, src, qname, dst)
			return c, err
		},
		RouteKey: func(src netip.Addr, qname string) string {
			r := d.Route(src, qname, netip.Addr{})
			return r.Kind + ":" + r.ClientID
		},
		Logf: log.Printf,
	})

	ros := routeros.New(routeros.Options{Logf: log.Printf})

	// apply pushes a config snapshot into every component. It runs once at
	// startup and after every successful Store.Update.
	prev := cfg
	apply := func(c *config.Config) {
		if err := d.Update(c); err != nil {
			log.Printf("config: %v", err)
		}
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
		ros.SetConfig(r.Enabled || os.Getenv("ROS_URL") != "",
			envOr("ROS_URL", r.URL), envOr("ROS_USER", r.User), envOr("ROS_PASS", r.Password), r.AddressList)
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

	hs := &http.Server{Addr: ":" + strconv.Itoa(int(p.UI)), Handler: ui, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("ui listening on %s", hs.Addr)
		if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
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
