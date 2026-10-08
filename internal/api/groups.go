package api

import (
	"net/http"
	"strings"

	"github.com/onlymaj/v2ray-client-go/internal/config"
	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/router"
)

type groupView struct {
	group.Group
	Current string  `json:"current"`
	Traffic Traffic `json:"traffic"`
}

func (s *server) groupView(g group.Group) groupView {
	if g.Members == nil {
		g.Members = []string{}
	}
	return groupView{Group: g, Current: s.rt.GroupCurrent(g.ID), Traffic: s.rt.Traffic("group:" + g.ID)}
}

func (s *server) listGroups(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Get()
	out := make([]groupView, 0, len(cfg.Groups))
	for _, g := range cfg.Groups {
		out = append(out, s.groupView(g))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getGroup(w http.ResponseWriter, r *http.Request) {
	g := s.store.Get().Group(r.PathValue("id"))
	if g == nil {
		writeErr(w, http.StatusNotFound, "group not found")
		return
	}
	writeJSON(w, http.StatusOK, s.groupView(*g))
}

func decodeGroup(r *http.Request) (group.Group, error) {
	var g group.Group
	if err := decode(r, &g); err != nil {
		return g, err
	}
	if strings.TrimSpace(g.Name) == "" {
		return g, errf(http.StatusBadRequest, "name is required")
	}
	if g.Members == nil {
		g.Members = []string{}
	}
	return g, nil
}

func (s *server) createGroup(w http.ResponseWriter, r *http.Request) {
	g, err := decodeGroup(r)
	if err != nil {
		writeError(w, err)
		return
	}
	g.ID = config.NewID()
	if err := s.update(func(cfg *config.Config) error {
		cfg.Groups = append(cfg.Groups, g)
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.groupView(g))
}

func (s *server) putGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	g, err := decodeGroup(r)
	if err != nil {
		writeError(w, err)
		return
	}
	g.ID = id
	if err := s.update(func(cfg *config.Config) error {
		old := cfg.Group(id)
		if old == nil {
			return errf(http.StatusNotFound, "group not found")
		}
		*old = g
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.groupView(g))
}

func (s *server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.update(func(cfg *config.Config) error {
		if cfg.Group(id) == nil {
			return errf(http.StatusNotFound, "group not found")
		}
		for _, rl := range cfg.Rules {
			if rl.Target.Kind == router.KindGroup && rl.Target.ID == id {
				return errf(http.StatusConflict, "group is used by a rule")
			}
		}
		out := cfg.Groups[:0]
		for _, g := range cfg.Groups {
			if g.ID != id {
				out = append(out, g)
			}
		}
		cfg.Groups = out
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, rulesOut(s.store.Get().Rules))
}

func rulesOut(rules []router.Rule) []router.Rule {
	if rules == nil {
		return []router.Rule{}
	}
	return rules
}

// putRules replaces the whole ordered rule list. Rules without an ID get one.
func (s *server) putRules(w http.ResponseWriter, r *http.Request) {
	var rules []router.Rule
	if err := decode(r, &rules); err != nil {
		writeError(w, err)
		return
	}
	for i := range rules {
		if rules[i].ID == "" {
			rules[i].ID = config.NewID()
		}
	}
	if err := s.update(func(cfg *config.Config) error {
		cfg.Rules = rules
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rulesOut(rules))
}
