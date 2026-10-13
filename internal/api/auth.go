package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
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
	cookieName = "nv2_session"
	sessionTTL = 7 * 24 * time.Hour
	// sessionIdle ends a session not used for this long (sliding), within
	// the sessionTTL cap.
	sessionIdle   = 12 * time.Hour
	loginAttempts = 5 // per IP and loginWindow
	loginWindow   = time.Minute
	// globalAttempts caps login attempts from all IPs together per
	// loginWindow, so rotating source addresses (e.g. IPv6 privacy
	// addresses) does not multiply the guess rate. The trade-off: a flood
	// from many addresses also blocks a new admin device until it stops.
	// IPs that logged in successfully before (trustedIPs) are exempt from
	// this cap (not from the per-IP one), so the usual admin device keeps
	// working during a flood.
	globalAttempts = 30
	maxTrusted     = 16
	maxLoginBody   = 1 << 10
)

type auth struct {
	salt []byte
	hash []byte

	hashMu sync.Mutex // one scrypt at a time, to cap memory

	mu       sync.Mutex
	sessions map[string]*session   // token -> session
	limits   map[string]*rateEntry // client IP -> attempts in the window
	global   rateEntry             // attempts from all IPs
	trusted  map[string]time.Time  // IP -> last successful login
	now      func() time.Time
}

// session is bound to the client IP it logged in from.
type session struct {
	ip       string
	expires  time.Time // hard cap: login + sessionTTL
	lastSeen time.Time // for sessionIdle
}

func (e *session) expired(now time.Time) bool {
	return !now.Before(e.expires) || now.Sub(e.lastSeen) >= sessionIdle
}

type rateEntry struct {
	start    time.Time
	n        int
	inflight bool // a login from this IP is being checked
}

// docPassword is the placeholder in docs/routeros.md. Its commands are made
// to be pasted, and the repository is public.
const docPassword = "change-me-long-random"

// minPassword is the length below which a start-up warning is logged. The
// limiter allows about 43,000 guesses a day from several addresses.
const minPassword = 10

// logf is a var so tests can capture it.
var logf = log.Printf

// loginLog limits the log lines for failed and refused logins: a flood of
// guesses must show in the container log without filling it.
var loginLog struct {
	sync.Mutex
	start   time.Time
	n, more int
}

const (
	loginLogBurst  = 5
	loginLogWindow = time.Minute
)

func logLogin(what, ip string) {
	l := &loginLog
	l.Lock()
	defer l.Unlock()
	now := time.Now()
	if now.Sub(l.start) >= loginLogWindow {
		if l.more > 0 {
			logf("api: %d more failed or refused logins not logged", l.more)
		}
		l.start, l.n, l.more = now, 0, 0
	}
	if l.n >= loginLogBurst {
		l.more++
		return
	}
	l.n++
	logf("api: %s from %s", what, ip)
}

func newAuth(password string) (*auth, error) {
	if password == "" {
		return nil, errors.New("api: ADMIN_PASSWORD is empty")
	}
	if password == docPassword {
		return nil, errors.New("api: ADMIN_PASSWORD is the example value from the documentation; set your own")
	}
	if len(password) < minPassword {
		logf("api: warning: ADMIN_PASSWORD is shorter than %d characters; anyone who can reach the UI can guess it in time", minPassword)
	}
	a := &auth{
		salt:     make([]byte, 16),
		sessions: map[string]*session{},
		limits:   map[string]*rateEntry{},
		trusted:  map[string]time.Time{},
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

// begin counts a login attempt from ip before the password is checked, so
// parallel requests cannot all pass the limit. It refuses the attempt (with
// the time to wait) when ip has used its loginAttempts, already has a login
// in flight, or when all IPs together have used globalAttempts. Otherwise
// the caller must call done with the result.
func (a *auth) begin(ip string) (bool, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	e := a.limits[ip]
	if e != nil && now.Sub(e.start) >= loginWindow {
		e.start, e.n = now, 0
	}
	if e != nil && e.inflight {
		return false, time.Second
	}
	if e != nil && e.n >= loginAttempts {
		return false, e.start.Add(loginWindow).Sub(now)
	}
	if now.Sub(a.global.start) >= loginWindow {
		a.global = rateEntry{start: now}
	}
	if _, ok := a.trusted[ip]; !ok && a.global.n >= globalAttempts {
		return false, a.global.start.Add(loginWindow).Sub(now)
	}
	if e == nil {
		// Only begun attempts add entries, and the global cap bounds those
		// per window, so evicting stale ones keeps the map small.
		if len(a.limits) >= 4*globalAttempts {
			for k, x := range a.limits {
				if !x.inflight && now.Sub(x.start) >= loginWindow {
					delete(a.limits, k)
				}
			}
		}
		e = &rateEntry{start: now}
		a.limits[ip] = e
	}
	e.n++
	e.inflight = true
	a.global.n++
	return true, 0
}

// done ends the attempt started by begin. A success clears the IP's count
// and marks it trusted.
func (a *auth) done(ip string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.limits[ip]; e != nil {
		e.inflight = false
	}
	if !ok {
		return
	}
	delete(a.limits, ip)
	now := a.now()
	if _, known := a.trusted[ip]; !known && len(a.trusted) >= maxTrusted {
		oldest := ""
		for k, t := range a.trusted {
			if oldest == "" || t.Before(a.trusted[oldest]) {
				oldest = k
			}
		}
		delete(a.trusted, oldest)
	}
	a.trusted[ip] = now
}

// newSession starts a session for a login from ip.
func (a *auth) newSession(ip string) string {
	var b [32]byte
	rand.Read(b[:])
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, e := range a.sessions {
		if e.expired(now) {
			delete(a.sessions, k)
		}
	}
	a.sessions[tok] = &session{ip: ip, expires: now.Add(sessionTTL), lastSeen: now}
	return tok
}

// valid reports whether r carries a live session from the IP that created
// it, and extends the session's idle timeout.
func (a *auth) valid(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.sessions[c.Value]
	if !ok {
		return false
	}
	now := a.now()
	if e.expired(now) {
		delete(a.sessions, c.Value)
		return false
	}
	// A cookie used from another IP is refused but not revoked, so a
	// stolen copy cannot log the owner out.
	if e.ip != clientIP(r) {
		return false
	}
	e.lastSeen = now
	return true
}

// alive reports whether the session r carries is still valid for r's IP,
// without counting as use (so a long-lived SSE stream doesn't keep the
// session from reaching its idle timeout).
func (a *auth) alive(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.sessions[c.Value]
	return ok && !e.expired(a.now()) && e.ip == clientIP(r)
}

// drop ends the session r carries, but only for a request from the IP the
// session is bound to: like valid, a stolen copy cannot log the owner out.
func (a *auth) drop(r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.mu.Lock()
		if e, ok := a.sessions[c.Value]; ok && e.ip == clientIP(r) {
			delete(a.sessions, c.Value)
		}
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

// loginReadTimeout is how long the login body may take to arrive. A
// variable for tests.
var loginReadTimeout = 5 * time.Second

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	// Before login a request must not be able to wait: one that announced
	// a body and never sent it sat until the server's read timeout with
	// its parsed headers in memory (round 17).
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(loginReadTimeout))
	if r.ContentLength < 0 || r.ContentLength > maxLoginBody {
		// Close: net/http would otherwise read the unread body before
		// it sends the reply.
		w.Header().Set("Connection", "close")
		writeErr(w, http.StatusBadRequest, "invalid login request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	var body struct {
		Password string `json:"password"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, err)
		return
	}
	ip := clientIP(r)
	if ok, wait := s.auth.begin(ip); !ok {
		logLogin("login refused by the rate limit", ip)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		writeErr(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}
	ok := s.auth.check(body.Password)
	s.auth.done(ip, ok)
	if !ok {
		logLogin("failed login", ip) // never the submitted password
		writeErr(w, http.StatusUnauthorized, "wrong password")
		return
	}
	setCookie(w, r, s.auth.newSession(ip), int(sessionTTL.Seconds()))
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
