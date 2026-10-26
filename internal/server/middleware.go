// SPDX-License-Identifier: 0BSD

package server

import (
	"fmt"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/Sudo-Ivan/saves/pkg/api"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// altSvc advertises HTTP/3 on TCP responses when configured.
func (s *Server) altSvc(next http.Handler) http.Handler {
	v := s.Cfg.Listen.AltSvc
	if v == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil || r.ProtoMajor < 3 {
			w.Header().Set("Alt-Svc", v)
		}
		next.ServeHTTP(w, r)
	})
}

// secureHeaders applies the standard header set.
func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// cors applies the strict allowlist when enabled.
func (s *Server) cors(next http.Handler) http.Handler {
	if !s.Cfg.CORS.Enabled {
		return next
	}
	allowed := map[string]bool{}
	for _, o := range s.Cfg.CORS.AllowedOrigins {
		allowed[o] = true
	}
	methods := joinOr(s.Cfg.CORS.AllowedMethods, "GET, PUT, POST, DELETE, PATCH, HEAD, OPTIONS")
	headers := joinOr(s.Cfg.CORS.AllowedHeaders, "Authorization, Content-Type, If-Match, Range, X-Request-Id")
	maxAge := s.Cfg.CORS.MaxAge.Duration()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Add("Vary", "Origin")
		if origin != "" && allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Access-Control-Allow-Headers", headers)
			if maxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%.0f", maxAge.Seconds()))
			}
		}
		if r.Method == http.MethodOptions && origin != "" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func joinOr(v []string, def string) string {
	if len(v) == 0 {
		return def
	}
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// requestLog assigns the id and writes an access line. The writer
// wrapper keeps Unwrap, Flush and ReadFrom available so inner code
// like http.ServeContent keeps its fast paths.
func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestID(r)
		w.Header().Set("X-Request-Id", id)
		sw := &statusWriter{ResponseWriter: w, status: 200}
		t0 := time.Now()
		next.ServeHTTP(sw, r)
		if s.accessLog {
			s.Log.Info("request", "id", id, "method", r.Method, "path", r.URL.Path,
				"status", sw.status, "ip", s.clientIP(r), "ms", time.Since(t0).Milliseconds())
			if s.collector != nil {
				s.collector.Count(int64(sw.status), 0, 0)
			}
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the real writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Flush passes through.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom passes through so sendfile stays enabled.
func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}

// recover converts panics to 500 problems on /v1 and styled error
// pages elsewhere.
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic", "err", rec, "path", r.URL.Path)
				if s.web != nil && !strings.HasPrefix(r.URL.Path, "/v1/") {
					wv := &webReq{s: s, w: w, r: r, web: s.web}
					wv.errorPage(500)
					return
				}
				s.writeProblem(w, r, fmt.Errorf("panic: %v", rec))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Rolling request deadlines. A moving client (read or write) keeps
// earning deadline extensions at min_throughput; a stalled client is
// cut. All deadlines are cleared when the request ends so keep-alive
// connections are never poisoned. HTTP/2 and HTTP/3 ignore per-stream
// deadlines via ErrNotSupported.

func (s *Server) wrapDeadline(next http.Handler) http.Handler {
	minBps := s.Cfg.Listen.MinThroughput.Int64()
	if minBps <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		r.Body = &deadlineBody{r: r.Body, rc: rc, minBps: minBps}
		dw := &deadlineWriter{ResponseWriter: w, rc: rc, minBps: minBps}
		defer clearDeadline(rc)
		next.ServeHTTP(dw, r)
	})
}

func clearDeadline(rc *http.ResponseController) {
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
}

func windowFor(minBps, n int64) time.Duration {
	if n <= 0 {
		return 5 * time.Second
	}
	w := time.Duration(n/minBps) * time.Second
	if w < 5*time.Second {
		w = 5 * time.Second
	}
	return w
}

type deadlineBody struct {
	r      io.ReadCloser
	rc     *http.ResponseController
	minBps int64
}

func (d *deadlineBody) Read(p []byte) (int, error) {
	_ = d.rc.SetReadDeadline(time.Now().Add(windowFor(d.minBps, int64(len(p)))))
	n, err := d.r.Read(p)
	if err != nil { // io.EOF or real error: clear stale deadline
		_ = d.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}

func (d *deadlineBody) Close() error {
	_ = d.rc.SetReadDeadline(time.Time{})
	return d.r.Close()
}

type deadlineWriter struct {
	http.ResponseWriter
	rc     *http.ResponseController
	minBps int64
}

func (d *deadlineWriter) Unwrap() http.ResponseWriter { return d.ResponseWriter }

func (d *deadlineWriter) Flush() {
	if f, ok := d.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	_ = d.rc.SetWriteDeadline(time.Now().Add(windowFor(d.minBps, int64(len(p)))))
	return d.ResponseWriter.Write(p)
}

func (d *deadlineWriter) ReadFrom(r io.Reader) (int64, error) {
	// Sized copy when Content-Length is known lets sendfile run
	// under one deadline; otherwise copy in bounded steps so each
	// Write earns its own extension.
	if cl := d.ResponseWriter.Header().Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			_ = d.rc.SetWriteDeadline(time.Now().Add(windowFor(d.minBps, n)))
			if rf, ok := d.ResponseWriter.(io.ReaderFrom); ok {
				return rf.ReadFrom(r)
			}
		}
	}
	return io.Copy(writerOnly{d}, r)
}

type writerOnly struct{ io.Writer }

// Handler assembles the middleware chain. /v1 goes to the API mux,
// everything else to the web handler when enabled.
func (s *Server) Handler() http.Handler {
	api := s.cors(s.maintenanceMW(s.bandwidthMW(s.Mux())))
	var h http.Handler = api
	if s.web != nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v1/") {
				api.ServeHTTP(w, r)
				return
			}
			s.webServe(w, r)
		})
	} else {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v1/") {
				api.ServeHTTP(w, r)
				return
			}
			api.ServeHTTP(w, r)
		})
	}
	h = s.ipBlockMW(h)
	h = s.altSvc(h)
	h = s.clientCtx(h)
	h = s.requestLog(h)
	h = s.secureHeaders(h)
	h = s.wrapDeadline(h)
	h = s.recover(h)
	return h
}

// clientCtx records the caller address and user agent for audit events.
func (s *Server) clientCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := netx.ClientIPReal(r, s.trustedCIDRs(), s.Cfg.Proxy.RealIPHeader).String()
		next.ServeHTTP(w, r.WithContext(service.WithClient(r.Context(), ip, r.UserAgent())))
	})
}

// maintenanceMW returns 503 for /v1 writes while maintenance mode is
// on. Reads, /v1/admin, /v1/me and token routes still work.
func (s *Server) maintenanceMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") || r.Method == "GET" || r.Method == "HEAD" {
			next.ServeHTTP(w, r)
			return
		}
		sv := s.siteVals()
		if !sv.Maintenance {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if p == "/v1/me" || p == "/v1/register" || strings.HasPrefix(p, "/v1/admin") || strings.HasPrefix(p, "/v1/tokens") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Retry-After", "60")
		s.writeProblem(w, r, &api.Problem{Code: api.CodeMaintenance,
			Title: "maintenance", Status: 503, Detail: sv.MaintenanceMsg})
	})
}
