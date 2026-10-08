package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// scrypt cost. N=16384, r=8 needs 16 MB per hash (N=32768 would need 32 MB,
// too much for a container that aims at < 20 MB RSS). Hashing is serialized
// by auth.hashMu, so at most one 16 MB buffer exists at a time. The hash is
// never persisted, so this cost only guards against a memory dump.
var scryptN = 16384

const (
	cookieName    = "nv2_session"
	sessionTTL    = 7 * 24 * time.Hour
	loginAttempts = 5
	loginWindow   = time.Minute
)

type auth struct {
	salt []byte
	hash []byte

	hashMu sync.Mutex // one scrypt at a time, to cap memory

	mu       sync.Mutex
	sessions map[string]time.Time  // token -> expiry
	limits   map[string]*rateEntry // client IP -> failed attempts
	now      func() time.Time
}

type rateEntry struct {
	start time.Time
	n     int
}

func newAuth(password string) (*auth, error) {
	if password == "" {
		return nil, errors.New("api: ADMIN_PASSWORD is empty")
	}
	a := &auth{
		salt:     make([]byte, 16),
		sessions: map[string]time.Time{},
		limits:   map[string]*rateEntry{},
		now:      time.Now,
	}
	rand.Read(a.salt)
	h, err := a.derive(password)
	if err != nil {
		return nil, err
	}
	a.hash = h
	return a, nil
}

func (a *auth) derive(password string) ([]byte, error) {
	a.hashMu.Lock()
	defer a.hashMu.Unlock()
	return scrypt.Key([]byte(password), a.salt, scryptN, 8, 1, 32)
}

// check always runs scrypt, so a wrong password and a correct one take the
// same time.
func (a *auth) check(password string) bool {
	h, err := a.derive(password)
	return err == nil && subtle.ConstantTimeCompare(h, a.hash) == 1
}

// allow reports whether ip may try to log in, and if not, how long to wait.
func (a *auth) allow(ip string) (bool, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	e := a.limits[ip]
	if e == nil || now.Sub(e.start) >= loginWindow {
		return true, 0
	}
	if e.n >= loginAttempts {
		return false, e.start.Add(loginWindow).Sub(now)
	}
	return true, 0
}

func (a *auth) fail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if len(a.limits) > 1024 {
		for k, e := range a.limits {
			if now.Sub(e.start) >= loginWindow {
				delete(a.limits, k)
			}
		}
	}
	e := a.limits[ip]
	if e == nil || now.Sub(e.start) >= loginWindow {
		e = &rateEntry{start: now}
		a.limits[ip] = e
	}
	e.n++
}

func (a *auth) newSession() string {
	var b [32]byte
	rand.Read(b[:])
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, k)
		}
	}
	a.sessions[tok] = now.Add(sessionTTL)
	return tok
}

func (a *auth) valid(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[c.Value]
	if ok && a.now().After(exp) {
		delete(a.sessions, c.Value)
		return false
	}
	return ok
}

func (a *auth) drop(r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func setCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if ok, wait := s.auth.allow(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		writeErr(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, err)
		return
	}
	if !s.auth.check(body.Password) {
		s.auth.fail(ip)
		writeErr(w, http.StatusUnauthorized, "wrong password")
		return
	}
	setCookie(w, r, s.auth.newSession(), int(sessionTTL.Seconds()))
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	s.auth.drop(r)
	setCookie(w, r, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	if !s.auth.valid(r) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"user": "admin"})
}

func (s *server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.valid(r) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
