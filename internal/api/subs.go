package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/router"
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
		// The reply to this request can be an error although the
		// subscription was stored (the first fetch is a second save); a
		// retry then made a duplicate (round 25).
		for _, o := range cfg.Subscriptions {
			if o.URL == sub.URL {
				return errf(http.StatusConflict, "a subscription with this URL already exists")
			}
		}
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

// subWait is how long a refresh waits for the ones before it. A variable
// for tests.
var subWait = time.Minute

var errBusy = errors.New("other subscriptions are still being fetched; try again")

// matchKey identifies "the same server" across subscription refreshes.
func matchKey(c config.Client) string {
	return strings.Join([]string{c.Protocol, c.Address, strconv.Itoa(int(c.Port)), c.UUID,
		c.Network, c.Path, c.ServiceName}, "\x00")
}

// refresh downloads the subscription and replaces its clients. Clients that
// match an old one on matchKey keep its ID and enabled flag, so groups and
// rules keep pointing at them; vanished ones are removed with their
// references, except those a rule targets, which are kept; new ones are enabled and appended to the "default" group.
// A failed download, or one with no usable links, only records lastError.
func (s *server) refresh(r *http.Request, id string) (config.Subscription, error) {
	sub := findSub(s.store.Get(), id)
	if sub == nil {
		return config.Subscription{}, errf(http.StatusNotFound, "subscription not found")
	}
	var res share.Result
	ferr := func() error {
		// The wait has an end: the reply must be written within the
		// server's write timeout, and a fetch can take 30 s (round 19).
		wait := time.NewTimer(subWait)
		defer wait.Stop()
		select {
		case s.subSem <- struct{}{}:
			defer func() { <-s.subSem }() // deferred: a panic must not leave it held
		case <-wait.C:
			return errBusy
		case <-r.Context().Done():
			return r.Context().Err() // the browser left while this one waited its turn
		}
		body, err := s.fetch(r.Context(), sub.URL)
		if err != nil {
			return err
		}
		res = s.usable(share.DecodeSubscription(body))
		if err := tooManyLinks(res); err != nil {
			return err
		}
		if len(res.Clients) == 0 {
			return fmt.Errorf("no supported links (%d errors, %d skipped)", len(res.Errors), res.Skipped)
		}
		return nil
	}()
	now := time.Now().UTC().Format(time.RFC3339)

	var out config.Subscription
	var fresh []string
	err := s.update(func(cfg *config.Config) error {
		sp := findSub(cfg, id)
		if sp == nil {
			return errf(http.StatusNotFound, "subscription not found")
		}
		sp.LastUpdate = now
		sp.Note = ""
		if ferr != nil {
			sp.LastError = clip(ferr.Error(), maxLastError)
			if r.Context().Err() != nil {
				// The browser left: not a failure of the subscription.
				sp.LastError = "the refresh was cancelled before it finished"
			}
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
		// A client that left the subscription goes, except one a rule
		// points at. Removing it would remove the rule too, and that
		// traffic would follow the later rules (perhaps direct) on the
		// provider's say. Kept, it most likely stops answering and the
		// kill switch applies; the admin deletes it and sees the warning.
		ruled := map[string]bool{}
		for _, r := range cfg.Rules {
			if r.Target.Kind == router.KindClient {
				ruled[r.Target.ID] = true
			}
		}
		kept := 0
		for _, sc := range sortedGone(old) {
			if ruled[sc.ID] {
				cfg.Clients = append(cfg.Clients, sc)
				kept++
			} else {
				cfg.RemoveClient(sc.ID)
			}
		}
		if g := cfg.Group("default"); g != nil {
			g.Members = append(g.Members, fresh...)
		}

		sp.Count = len(next) + kept
		sp.LastError = ""
		var notes []string
		if n := len(res.Errors); n > 0 {
			notes = append(notes, fmt.Sprintf("%d links failed to parse", n))
		}
		if kept > 0 {
			notes = append(notes, fmt.Sprintf("%d clients no longer in the subscription are kept because rules use them", kept))
		}
		sp.Note = strings.Join(notes, "; ")
		out = *sp
		return nil
	})
	var he *httpError
	// A config that would pass config.MaxFileSize is refused by the store,
	// after the callback, and is recorded the same way (round 22).
	if errors.As(err, &he) && he.code == http.StatusBadRequest || errors.Is(err, config.ErrTooLarge) {
		// The new clients do not fit the config (over the client limit,
		// for one). Recorded like a failed download: before round 18 the
		// request failed and the subscription showed nothing.
		msg := clip(err.Error(), maxLastError)
		record := func() error {
			return s.update(func(cfg *config.Config) error {
				sp := findSub(cfg, id)
				if sp == nil {
					return errf(http.StatusNotFound, "subscription not found")
				}
				sp.LastUpdate, sp.LastError = now, msg
				out = *sp
				return nil
			})
		}
		// A config at its size limit may have no room for the message
		// either (round 23). Within some 80 bytes of the limit not even
		// the short one fits, and the request fails with the size error.
		if err = record(); errors.Is(err, config.ErrTooLarge) {
			msg = "too large"
			err = record()
		}
	}
	if err != nil {
		return config.Subscription{}, err
	}
	// No CheckNow for the new clients: the health checker checks a new
	// client at once anyway, in the lane for untrusted clients. Here they
	// would queue in the lane of the "check now" button and of the admin's
	// own saves, 10 s each when their servers stall (round 16).
	return out, nil
}

// maxLastError bounds a stored fetch error. Its text can come from the
// subscription server (a redirect target, for one) and is written to
// config.json on every save.
const maxLastError = 300

// clip cuts s to at most n bytes of valid UTF-8.
func clip(s string, n int) string {
	if len(s) <= n {
		return strings.ToValidUTF8(s, "")
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

// sortedGone returns the clients left in old in a stable order.
func sortedGone(old map[string][]config.Client) []config.Client {
	var out []config.Client
	for _, l := range old {
		out = append(out, l...)
	}
	slices.SortFunc(out, func(a, b config.Client) int { return strings.Compare(a.ID, b.ID) })
	return out
}
