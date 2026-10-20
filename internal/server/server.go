// SPDX-License-Identifier: 0BSD

// Package server provides the saves HTTP front end: routing, auth,
// middleware, protocol listeners (h1/h2/h3/h2c), TLS modes, and the
// ops listener.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/metrics"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/ratelimit"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Server bundles the dependencies handlers need.
type Server struct {
	Svc   *service.Service
	Auth  auth.Chain
	Reg   *auth.Registration
	Meta  meta.Store
	Blob  blob.Store
	Log   *slog.Logger
	Met   *metrics.Metrics
	Cfg   *config.Config
	Clock func() time.Time

	// rate limiting
	ipLimit     *ratelimit.Limiter
	principalRL *ratelimit.Limiter
	accessLog   bool
	ready       chan struct{}
	draining    atomic.Bool
}

// Options for New.
type Options struct {
	Clock     func() time.Time
	Logger    *slog.Logger
	Metrics   *metrics.Metrics
	LimiterIP *ratelimit.Limiter
}

// New builds a Server.
func New(svc *service.Service, m meta.Store, b blob.Store, a auth.Chain, reg *auth.Registration, cfg *config.Config, o Options) *Server {
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Metrics == nil {
		o.Metrics = metrics.New(cfg.Metrics.Namespace, "dev")
	}
	s := &Server{
		Svc: svc, Meta: m, Blob: b, Auth: a, Reg: reg, Log: o.Logger,
		Met: o.Metrics, Cfg: cfg, Clock: o.Clock,
		ipLimit:     o.LimiterIP,
		principalRL: ratelimit.New(100, 200, 1<<16, o.Clock),
		accessLog:   cfg.Log.Access,
		ready:       make(chan struct{}),
	}
	if s.ipLimit == nil {
		s.ipLimit = ratelimit.New(50, 100, 1<<16, o.Clock)
	}
	close(s.ready)
	return s
}

// Mux returns the main API mux.
func (s *Server) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/me", s.hMe)
	mux.HandleFunc("POST /v1/register", s.hRegister)
	mux.HandleFunc("GET /v1/vault", s.hVaultGet)
	mux.HandleFunc("PUT /v1/vault", s.hVaultPut)
	mux.HandleFunc("DELETE /v1/vault", s.hVaultDelete)
	mux.HandleFunc("GET /v1/apps", s.hApps)
	mux.HandleFunc("GET /v1/apps/{app}/slots", s.hSlots)
	mux.HandleFunc("GET /v1/apps/{app}/slots/{slot}", s.hSlot)
	mux.HandleFunc("DELETE /v1/apps/{app}/slots/{slot}", s.hSlotDelete)
	mux.HandleFunc("POST /v1/apps/{app}/slots/{slot}/snapshots", s.hBegin)
	mux.HandleFunc("GET /v1/apps/{app}/slots/{slot}/snapshots", s.hListSnapshots)
	mux.HandleFunc("GET /v1/apps/{app}/slots/{slot}/snapshots/{id}", s.hGetSnapshot)
	mux.HandleFunc("DELETE /v1/apps/{app}/slots/{slot}/snapshots/{id}", s.hDeleteSnapshot)
	mux.HandleFunc("POST /v1/apps/{app}/slots/{slot}/snapshots/{id}/commit", s.hCommit)
	mux.HandleFunc("PUT /v1/apps/{app}/slots/{slot}/snapshots/{id}/chunks/{hash}", s.hPutChunk)
	mux.HandleFunc("GET /v1/apps/{app}/slots/{slot}/snapshots/{id}/files/{path...}", s.hGetFile)
	mux.HandleFunc("HEAD /v1/apps/{app}/slots/{slot}/snapshots/{id}/files/{path...}", s.hGetFile)
	mux.HandleFunc("GET /v1/apps/{app}/slots/{slot}/snapshots/{id}/archive.tar", s.hArchive)
	mux.HandleFunc("GET /v1/apps/{app}/slots/{slot}/snapshots/{a}/diff/{b}", s.hDiff)
	mux.HandleFunc("GET /v1/apps/{app}/chunks/{hash}", s.hGetChunk)
	mux.HandleFunc("HEAD /v1/apps/{app}/chunks/{hash}", s.hGetChunk)
	mux.HandleFunc("GET /v1/admin/users", s.hAdminUsers)
	mux.HandleFunc("GET /v1/admin/users/{id}", s.hAdminUser)
	mux.HandleFunc("PATCH /v1/admin/users/{id}", s.hAdminPatchUser)
	mux.HandleFunc("DELETE /v1/admin/users/{id}", s.hAdminDeleteUser)
	mux.HandleFunc("GET /v1/admin/users/{id}/tokens", s.hAdminListTokens)
	mux.HandleFunc("POST /v1/admin/users/{id}/tokens", s.hAdminCreateToken)
	mux.HandleFunc("DELETE /v1/admin/tokens/{id}", s.hAdminRevokeToken)
	mux.HandleFunc("GET /v1/admin/stats", s.hAdminStats)
	mux.HandleFunc("POST /v1/admin/gc", s.hAdminGC)
	mux.HandleFunc("GET /v1/tokens", s.hMyTokens)
	mux.HandleFunc("POST /v1/tokens", s.hMyTokenCreate)
	mux.HandleFunc("DELETE /v1/tokens/{id}", s.hMyTokenRevoke)
	return mux
}

// requestID returns or mints one.
func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 128 {
		return id
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// writeJSON emits a JSON body.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeProblem emits RFC 9457.
func (s *Server) writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	var p *api.Problem
	if !errors.As(err, &p) {
		switch {
		case errors.Is(err, meta.ErrNotFound):
			p = &api.Problem{Code: api.CodeNotFound, Title: "not found", Status: 404}
		case errors.Is(err, auth.ErrUnauthorized), errors.Is(err, auth.ErrNoCredentials):
			w.Header().Set("WWW-Authenticate", `Bearer realm="saves"`)
			p = &api.Problem{Code: api.CodeUnauthorized, Title: "unauthorized", Status: 401}
		case errors.Is(err, auth.ErrForbidden):
			p = &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
		case errors.Is(err, auth.ErrRateLimited):
			w.Header().Set("Retry-After", "1")
			p = &api.Problem{Code: api.CodeRateLimited, Title: "rate limited", Status: 429}
		default:
			s.Log.Error("internal error", "err", err)
			p = &api.Problem{Code: api.CodeInternal, Title: "internal error", Status: 500}
		}
	}
	if p.Status == 429 {
		w.Header().Set("Retry-After", "1")
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// authn runs the auth chain plus per-IP limiter.
func (s *Server) authn(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	ip := s.clientIP(r)
	if ok, after := s.ipLimit.Allow(ip, 1); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", after.Seconds()+1))
		s.writeProblem(w, r, auth.ErrRateLimited)
		return auth.Principal{}, false
	}
	p, err := s.Auth.Authenticate(r.Context(), r)
	if err != nil {
		if !errors.Is(err, auth.ErrNoCredentials) {
			s.Met.AuthFail("reject")
		}
		s.writeProblem(w, r, err)
		return auth.Principal{}, false
	}
	return p, true
}

func (s *Server) clientIP(r *http.Request) string {
	return netx.IPPrefix(netx.ClientIP(r, s.trustedCIDRs()))
}

func (s *Server) trustedCIDRs() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range s.Cfg.Auth.Proxy.TrustedCIDRs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p)
		}
	}
	return out
}
