package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func get(h http.Handler, path, ae string) *http.Response {
	req := httptest.NewRequest("GET", path, nil)
	if ae != "" {
		req.Header.Set("Accept-Encoding", ae)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func body(r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func TestGzipNegotiation(t *testing.T) {
	h := New(fstest.MapFS{
		"index.html":        {Data: []byte("<html>")},
		"assets/app.js.gz":  {Data: gz("console.log(1)")},
		"assets/app.css":    {Data: []byte("a{}")},
		"assets/app.css.gz": {Data: gz("a{}")},
	})

	r := get(h, "/assets/app.js", "br, gzip;q=0.8")
	if r.Header.Get("Content-Encoding") != "gzip" || r.Header.Get("Vary") != "Accept-Encoding" ||
		r.Header.Get("Content-Type") != "text/javascript; charset=utf-8" ||
		r.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("gzip headers: %v", r.Header)
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(zr); string(b) != "console.log(1)" {
		t.Fatalf("gz body %q", b)
	}

	// Only .gz stored and no gzip support: decompressed on the fly.
	for _, ae := range []string{"", "identity", "gzip;q=0"} {
		r = get(h, "/assets/app.js", ae)
		if r.StatusCode != 200 || r.Header.Get("Content-Encoding") != "" || body(r) != "console.log(1)" {
			t.Fatalf("ae=%q: %d %v", ae, r.StatusCode, r.Header)
		}
	}

	// Plain file present: served as is.
	r = get(h, "/assets/app.css", "")
	if r.Header.Get("Content-Encoding") != "" || body(r) != "a{}" || r.Header.Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("plain: %v", r.Header)
	}

	// SPA fallback and index caching.
	for _, p := range []string{"/", "/clients/abc"} {
		r = get(h, p, "gzip")
		if r.StatusCode != 200 || body(r) != "<html>" || r.Header.Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s: %d %v", p, r.StatusCode, r.Header)
		}
	}
	if r = get(h, "/assets/missing.js", ""); r.StatusCode != 404 {
		t.Fatalf("missing asset: %d", r.StatusCode)
	}
}

func TestEmbeddedPlaceholder(t *testing.T) {
	r := get(Handler(), "/", "")
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("%d %v", r.StatusCode, r.Header)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := New(fstest.MapFS{"index.html": {Data: []byte("<html>")}})
	for _, p := range []string{"/", "/clients/abc", "/assets/missing.js"} {
		r := get(h, p, "")
		// The whole policy (round 17: only frame-ancestors was checked, so
		// dropping script-src, the XSS defence, passed).
		csp := "; " + r.Header.Get("Content-Security-Policy") + ";"
		for _, d := range []string{"default-src 'self'", "script-src 'self'", "connect-src 'self'", "base-uri 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, "; "+d+";") {
				t.Fatalf("%s: CSP lacks %q: %s", p, d, csp)
			}
		}
		if !strings.Contains(r.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			r.Header.Get("X-Frame-Options") != "DENY" || r.Header.Get("X-Content-Type-Options") != "nosniff" ||
			r.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s: %v", p, r.Header)
		}
	}
}

type headerSpy struct {
	http.ResponseWriter
	r    *http.Request
	seen int
}

func (s *headerSpy) Write(p []byte) (int, error) {
	s.seen = len(s.r.Header)
	return s.ResponseWriter.Write(p)
}

// Round 18: a client that asked for a UI file with 8 KiB of headers and
// never read the reply kept all of them parsed (about 170 KB) for as long
// as the write was blocked. Only the headers serving a file reads are kept.
func TestRequestHeadersDroppedBeforeTheBodyIsWritten(t *testing.T) {
	h := New(fstest.MapFS{"index.html": {Data: []byte("<html>")}, "assets/a.js.gz": {Data: gz("js")}})
	for _, p := range []string{"/", "/assets/a.js"} {
		req := httptest.NewRequest("GET", p, nil)
		for i := range 1000 {
			req.Header.Set("X-"+strings.Repeat("a", i%20)+string(rune('a'+i%26))+string(rune('a'+i/26%26)), "")
		}
		req.Header.Set("Accept-Encoding", "gzip")
		spy := &headerSpy{ResponseWriter: httptest.NewRecorder(), r: req}
		h.ServeHTTP(spy, req)
		if spy.seen == 0 || spy.seen > len(servedHeaders) {
			t.Errorf("%s: %d request headers held while the body is written", p, spy.seen)
		}
	}
	if r := get(h, "/assets/a.js", "gzip"); r.Header.Get("Content-Encoding") != "gzip" {
		t.Error("gzip no longer negotiated")
	}
}
