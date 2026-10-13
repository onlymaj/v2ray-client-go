package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/share"
)

type statusView struct {
	State       string `json:"state"` // "up" | "down" | "unknown" | "disabled"
	TCPMs       *int   `json:"tcpMs"` // null when unknown
	DelayMs     *int   `json:"delayMs"`
	LastError   string `json:"lastError"`
	LastSuccess string `json:"lastSuccess"` // RFC3339 or ""
	LastCheck   string `json:"lastCheck"`
}

type clientView struct {
	config.Client
	Status  statusView `json:"status"`
	Traffic Traffic    `json:"traffic"`
}

func msPtr(v int) *int {
	if v <= 0 {
		return nil
	}
	return &v
}

func timeStr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *server) clientView(c config.Client) clientView {
	st := s.rt.ClientStatus(c.ID)
	v := statusView{
		State: st.State, TCPMs: msPtr(st.TCPMs), DelayMs: msPtr(st.DelayMs), LastError: st.LastError,
		LastSuccess: timeStr(st.LastSuccess), LastCheck: timeStr(st.LastCheck),
	}
	if !c.Enabled {
		v.State = "disabled"
	} else if v.State == "" {
		v.State = "unknown"
	}
	if c.ALPN == nil {
		c.ALPN = []string{}
	}
	return clientView{Client: c, Status: v, Traffic: s.rt.Traffic("client:" + c.ID)}
}

func (s *server) listClients(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Get()
	out := make([]clientView, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		out = append(out, s.clientView(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getClient(w http.ResponseWriter, r *http.Request) {
	c := s.store.Get().Client(r.PathValue("id"))
	if c == nil {
		writeErr(w, http.StatusNotFound, "client not found")
		return
	}
	writeJSON(w, http.StatusOK, s.clientView(*c))
}

// validateClient checks protocol-level fields that config.Validate leaves
// to the dialer, so mistakes surface as 400 instead of a dead client.
func (s *server) validateClient(c *config.Client) error {
	if strings.TrimSpace(c.Name) == "" {
		return errf(http.StatusBadRequest, "name must not be empty")
	}
	if c.Network == "" {
		c.Network = "tcp"
	}
	if c.TLS == "" {
		c.TLS = "none"
	}
	sc := c.Share()
	if err := sc.Validate(); err != nil {
		return errf(http.StatusBadRequest, "%v", err)
	}
	c.Security = sc.Security // Validate stores the canonical VMess cipher
	if err := s.check(*c); err != nil {
		return errf(http.StatusBadRequest, "%v", err)
	}
	return nil
}

// usable moves the clients of res that no dialer can be built for (a uuid
// that is not a UUID, an unknown flow or fingerprint, a bad Reality key) to
// its errors, so a link is refused when it is imported instead of becoming
// a client that can never connect.
func (s *server) usable(res share.Result) share.Result {
	ok := res.Clients[:0:0]
	for _, sc := range res.Clients {
		if err := s.check(config.FromShare(sc)); err != nil {
			text := sc.Name
			if text == "" {
				text = sc.Address
			}
			res.Errors = append(res.Errors, share.LineError{Text: clip(text, 80), Err: err.Error()})
			continue
		}
		ok = append(ok, sc)
	}
	res.Clients = ok
	return res
}

func (s *server) createClient(w http.ResponseWriter, r *http.Request) {
	var c config.Client
	if err := decode(r, &c); err != nil {
		writeError(w, err)
		return
	}
	c.ID = config.NewID()
	c.SubscriptionID = ""
	c.Untrusted = false // saved through the form: the admin vouches for it
	if err := s.validateClient(&c); err != nil {
		writeError(w, err)
		return
	}
	if err := s.update(func(cfg *config.Config) error {
		cfg.Clients = append(cfg.Clients, c)
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	if c.Enabled {
		s.rt.CheckNow(c.ID)
	}
	writeJSON(w, http.StatusCreated, s.clientView(c))
}

func (s *server) putClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var c config.Client
	if err := decode(r, &c); err != nil {
		writeError(w, err)
		return
	}
	c.ID = id
	c.Untrusted = false // saved through the form: the admin vouches for it
	if err := s.validateClient(&c); err != nil {
		writeError(w, err)
		return
	}
	if err := s.update(func(cfg *config.Config) error {
		old := cfg.Client(id)
		if old == nil {
			return errf(http.StatusNotFound, "client not found")
		}
		c.SubscriptionID = old.SubscriptionID
		*old = c
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	if c.Enabled {
		s.rt.CheckNow(id)
	}
	writeJSON(w, http.StatusOK, s.clientView(c))
}

func (s *server) deleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.update(func(cfg *config.Config) error {
		if cfg.Client(id) == nil {
			return errf(http.StatusNotFound, "client not found")
		}
		cfg.RemoveClient(id)
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) toggleClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var c config.Client
	if err := s.update(func(cfg *config.Config) error {
		p := cfg.Client(id)
		if p == nil {
			return errf(http.StatusNotFound, "client not found")
		}
		p.Enabled = !p.Enabled
		c = *p
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	if c.Enabled {
		s.rt.CheckNow(id)
	}
	writeJSON(w, http.StatusOK, s.clientView(c))
}

func (s *server) checkClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.store.Get().Client(id) == nil {
		writeErr(w, http.StatusNotFound, "client not found")
		return
	}
	s.rt.CheckNow(id)
	w.WriteHeader(http.StatusAccepted)
}

func (s *server) clientLink(w http.ResponseWriter, r *http.Request) {
	c := s.store.Get().Client(r.PathValue("id"))
	if c == nil {
		writeErr(w, http.StatusNotFound, "client not found")
		return
	}
	link, err := c.Share().Link()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"link": link})
}

// importLinks adds every parsed link as a new enabled, untrusted client and
// appends it to the "default" group, if that group exists. Links whose
// (protocol, address, port, uuid) already exist are counted as skipped, as
// are unsupported schemes.
func (s *server) importLinks(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, err)
		return
	}
	// Like a subscription body, the pasted text may be base64 as a whole.
	res := s.usable(share.DecodeSubscription([]byte(body.Text)))
	if err := tooManyLinks(res); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var added []config.Client
	skipped := res.Skipped
	if err := s.update(func(cfg *config.Config) error {
		added, skipped = added[:0], res.Skipped
		seen := map[string]bool{}
		for _, c := range cfg.Clients {
			seen[dupKey(c)] = true
		}
		for _, sc := range res.Clients {
			c := config.FromShare(sc)
			c.Untrusted = true // pasted links are as untrusted as subscriptions
			if seen[dupKey(c)] {
				skipped++
				continue
			}
			seen[dupKey(c)] = true
			added = append(added, c)
		}
		cfg.Clients = append(cfg.Clients, added...)
		if g := cfg.Group("default"); g != nil {
			for _, c := range added {
				g.Members = append(g.Members, c.ID)
			}
		}
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	views := make([]clientView, 0, len(added))
	for _, c := range added { // checked at once by the health checker, see refresh
		views = append(views, s.clientView(c))
	}
	errs := res.Errors
	if errs == nil {
		errs = []share.LineError{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": views, "errors": errs, "skipped": skipped})
}

func dupKey(c config.Client) string {
	return c.Protocol + "\x00" + c.Address + "\x00" + strconv.Itoa(int(c.Port)) + "\x00" + c.UUID
}
