package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/config"
)

// routerOSView hides the password: GET returns "" plus passwordSet.
type routerOSView struct {
	config.RouterOS
	Password    string `json:"password"`
	PasswordSet bool   `json:"passwordSet"`
}

type settingsView struct {
	config.Settings
	RouterOS routerOSView `json:"routeros"`
}

func publicSettings(st config.Settings) settingsView {
	return settingsView{
		Settings: st,
		RouterOS: routerOSView{RouterOS: st.RouterOS, PasswordSet: st.RouterOS.Password != ""},
	}
}

func (s *server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, publicSettings(s.store.Get().Settings))
}

// putSettings replaces the settings. An empty routeros.password keeps the
// stored one, unless routeros.url or routeros.user changes: then the stored
// password is cleared, so a session cannot send it to another server.
func (s *server) putSettings(w http.ResponseWriter, r *http.Request) {
	var st config.Settings
	if err := decode(r, &st); err != nil {
		writeError(w, err)
		return
	}
	if err := s.update(func(cfg *config.Config) error {
		old := cfg.Settings.RouterOS
		if st.RouterOS.Password == "" && st.RouterOS.URL == old.URL && st.RouterOS.User == old.User {
			st.RouterOS.Password = old.Password
		}
		cfg.Settings = st
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, publicSettings(st))
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target, rng := q.Get("target"), q.Get("range")
	if target == "" {
		target = "total"
	}
	if rng == "" {
		rng = "1h"
	}
	switch rng {
	case "1m", "1h", "24h":
	default:
		writeErr(w, http.StatusBadRequest, "range must be 1m, 1h or 24h")
		return
	}
	cfg := s.store.Get()
	kind, id, _ := strings.Cut(target, ":")
	switch {
	case target == "total":
	case kind == "client" && cfg.Client(id) != nil:
	case kind == "group" && cfg.Group(id) != nil:
	case kind == "client" || kind == "group":
		writeErr(w, http.StatusNotFound, kind+" not found")
		return
	default:
		writeErr(w, http.StatusBadRequest, "target must be total, client:<id> or group:<id>")
		return
	}
	v, err := s.rt.Series(target, rng)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *server) connections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.rt.Connections())
}

var heartbeat = 15 * time.Second

// events streams Bus events as server-sent events until the client goes
// away.
func (s *server) events(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // outlive the server's WriteTimeout
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	ch, cancel := s.bus.Subscribe()
	defer cancel()
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("retry: 3000\n\n")); err != nil {
		return
	}
	if rc.Flush() != nil {
		return
	}
	tick := time.NewTicker(heartbeat)
	defer tick.Stop()
	for {
		var err error
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			// The session was checked when the stream opened; end the
			// stream once it is logged out or expires.
			if !s.auth.alive(r) {
				return
			}
			_, err = w.Write([]byte(": hb\n\n"))
		case e, ok := <-ch:
			if !ok {
				return
			}
			data, merr := json.Marshal(e.Data)
			if merr != nil {
				continue
			}
			_, err = w.Write([]byte("event: " + e.Type + "\ndata: " + string(data) + "\n\n"))
		}
		if err == nil {
			err = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}
