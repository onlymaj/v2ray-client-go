package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/share"
)

func (s *server) listSubs(w http.ResponseWriter, r *http.Request) {
	subs := s.store.Get().Subscriptions
	if subs == nil {
		subs = []config.Subscription{}
	}
	writeJSON(w, http.StatusOK, subs)
}

func findSub(cfg *config.Config, id string) *config.Subscription {
	for i := range cfg.Subscriptions {
		if cfg.Subscriptions[i].ID == id {
			return &cfg.Subscriptions[i]
		}
	}
	return nil
}

// createSub stores the subscription and fetches it right away. A failed
// fetch still creates it (201) with lastError set, so it can be retried.
func (s *server) createSub(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, err)
		return
	}
	u, err := url.Parse(strings.TrimSpace(body.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		writeErr(w, http.StatusBadRequest, "url must be an http or https URL")
		return
	}
	sub := config.Subscription{ID: config.NewID(), Name: strings.TrimSpace(body.Name), URL: u.String()}
	if sub.Name == "" {
		sub.Name = u.Hostname()
	}
	if err := s.update(func(cfg *config.Config) error {
		cfg.Subscriptions = append(cfg.Subscriptions, sub)
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	out, err := s.refresh(r, sub.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// deleteSub removes the subscription and all of its clients.
func (s *server) deleteSub(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.update(func(cfg *config.Config) error {
		if findSub(cfg, id) == nil {
			return errf(http.StatusNotFound, "subscription not found")
		}
		var ids []string
		for _, c := range cfg.Clients {
			if c.SubscriptionID == id {
				ids = append(ids, c.ID)
			}
		}
		for _, cid := range ids {
			cfg.RemoveClient(cid)
		}
		out := cfg.Subscriptions[:0]
		for _, sub := range cfg.Subscriptions {
			if sub.ID != id {
				out = append(out, sub)
			}
		}
		cfg.Subscriptions = out
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) refreshSub(w http.ResponseWriter, r *http.Request) {
	out, err := s.refresh(r, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// matchKey identifies "the same server" across subscription refreshes.
func matchKey(c config.Client) string {
	return strings.Join([]string{c.Protocol, c.Address, strconv.Itoa(int(c.Port)), c.UUID,
		c.Network, c.Path, c.ServiceName}, "\x00")
}

// refresh downloads the subscription and replaces its clients. Clients that
// match an old one on matchKey keep its ID and enabled flag, so groups and
// rules keep pointing at them; vanished ones are removed with their
// references; new ones are enabled and appended to the "default" group.
// A failed download, or one with no usable links, only records lastError.
func (s *server) refresh(r *http.Request, id string) (config.Subscription, error) {
	sub := findSub(s.store.Get(), id)
	if sub == nil {
		return config.Subscription{}, errf(http.StatusNotFound, "subscription not found")
	}
	body, ferr := s.fetch(r.Context(), sub.URL)
	var res share.Result
	if ferr == nil {
		res = share.DecodeSubscription(body)
		if ferr = tooManyLinks(res); ferr == nil && len(res.Clients) == 0 {
			ferr = fmt.Errorf("no supported links (%d errors, %d skipped)", len(res.Errors), res.Skipped)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)

	var out config.Subscription
	var fresh []string
	err := s.update(func(cfg *config.Config) error {
		sp := findSub(cfg, id)
		if sp == nil {
			return errf(http.StatusNotFound, "subscription not found")
		}
		sp.LastUpdate = now
		if ferr != nil {
			sp.LastError = ferr.Error()
			out = *sp
			return nil
		}

		old := map[string][]config.Client{}
		var others []config.Client
		for _, c := range cfg.Clients {
			if c.SubscriptionID == id {
				k := matchKey(c)
				old[k] = append(old[k], c)
			} else {
				others = append(others, c)
			}
		}
		next := make([]config.Client, 0, len(res.Clients))
		fresh = fresh[:0]
		for _, sc := range res.Clients {
			c := config.FromShare(sc)
			c.SubscriptionID = id
			// The provider never decides security exceptions: no
			// allowInsecure, and private server addresses stay blocked.
			c.Untrusted, c.AllowInsecure = true, false
			k := matchKey(c)
			if prev := old[k]; len(prev) > 0 {
				c.ID, c.Enabled = prev[0].ID, prev[0].Enabled
				old[k] = prev[1:]
			} else {
				fresh = append(fresh, c.ID)
			}
			next = append(next, c)
		}
		cfg.Clients = append(others, next...)
		for _, gone := range old {
			for _, c := range gone {
				cfg.RemoveClient(c.ID)
			}
		}
		if g := cfg.Group("default"); g != nil {
			g.Members = append(g.Members, fresh...)
		}

		sp.Count = len(next)
		sp.LastError = ""
		if n := len(res.Errors); n > 0 {
			sp.LastError = fmt.Sprintf("%d links failed to parse", n)
		}
		out = *sp
		return nil
	})
	if err != nil {
		return config.Subscription{}, err
	}
	for i, cid := range fresh {
		if i < maxCheckNow {
			s.rt.CheckNow(cid)
		}
	}
	return out, nil
}
