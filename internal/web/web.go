// Package web serves the built UI embedded from dist/ (the build copies
// web/dist here). Files may be stored only as "<name>.gz": they are sent
// compressed to clients that accept gzip and decompressed on the fly for
// the rest. Unknown paths without a file extension fall back to index.html.
package web

import (
	"compress/gzip"
	"embed"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed all:dist
var dist embed.FS

// Handler serves the embedded UI.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return New(sub)
}

// New serves the UI from fsys (root = the dist directory).
func New(fsys fs.FS) http.Handler {
	return &handler{fsys: fsys}
}

type handler struct{ fsys fs.FS }

var extraTypes = map[string]string{
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".woff":        "font/woff",
	".txt":         "text/plain; charset=utf-8",
	".webmanifest": "application/manifest+json",
	".map":         "application/json",
}

func contentType(name string) string {
	ext := path.Ext(name)
	if t, ok := extraTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

func (h *handler) exists(name string) bool {
	st, err := fs.Stat(h.fsys, name)
	return err == nil && !st.IsDir()
}

// csp allows only same-origin scripts (no inline scripts, no eval) and no
// framing. Inline styles stay allowed: uPlot and Radix set style attributes.
const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// setSecurityHeaders adds the headers sent with every UI response.
func setSecurityHeaders(hd http.Header) {
	hd.Set("Content-Security-Policy", csp)
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")
}

// servedHeaders are the request headers serving a file reads.
var servedHeaders = []string{"Accept-Encoding", "Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since"}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Only these are needed from here on. The rest (up to 8 KiB on the
	// wire, about 14 times that parsed) would otherwise be held for as
	// long as the client takes to read the file (round 18).
	kept := make(http.Header, len(servedHeaders))
	for _, k := range servedHeaders {
		if v := r.Header[k]; len(v) > 0 {
			kept[k] = v[:1]
		}
	}
	r.Header = kept
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if !h.exists(name) && !h.exists(name+".gz") {
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		name = "index.html" // SPA fallback
	}

	hd := w.Header()
	hd.Set("Content-Type", contentType(name))
	if strings.HasPrefix(name, "assets/") {
		hd.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		hd.Set("Cache-Control", "no-cache")
	}

	if h.exists(name + ".gz") {
		hd.Add("Vary", "Accept-Encoding")
		if acceptsGzip(r) {
			hd.Set("Content-Encoding", "gzip")
			h.serveFile(w, r, name+".gz")
			return
		}
		if !h.exists(name) {
			h.serveGunzip(w, r, name+".gz")
			return
		}
	}
	h.serveFile(w, r, name)
}

func (h *handler) serveFile(w http.ResponseWriter, r *http.Request, name string) {
	f, err := h.fsys.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if rs, ok := f.(io.ReadSeeker); ok {
		http.ServeContent(w, r, "", time.Time{}, rs)
		return
	}
	if r.Method != http.MethodHead {
		io.Copy(w, f)
	}
}

func (h *handler) serveGunzip(w http.ResponseWriter, r *http.Request, name string) {
	f, err := h.fsys.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		http.Error(w, "corrupt asset", http.StatusInternalServerError)
		return
	}
	defer zr.Close()
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		io.Copy(w, zr)
	}
}

// acceptsGzip reports whether Accept-Encoding allows gzip (q > 0).
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		enc = strings.TrimSpace(enc)
		if enc != "gzip" && enc != "*" {
			continue
		}
		q := strings.ReplaceAll(strings.TrimSpace(params), " ", "")
		if q == "q=0" || q == "q=0.0" || q == "q=0.00" || q == "q=0.000" {
			return false
		}
		return true
	}
	return false
}
