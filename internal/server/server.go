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
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/gc"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/metrics"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/ratelimit"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/Sudo-Ivan/saves/internal/settings"
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

	// Version is shown on the admin page only.
	Version string

	// rate limiting
	ipLimit     *ratelimit.Limiter
	principalRL *ratelimit.Limiter
	accessLog   bool
	ready       chan struct{}
	draining    atomic.Bool
	web         *webUI
	bw          *bwManager
	settings    interface {
		Effective() settings.Values
	}
	auditor *Auditor
	blocks  *ipBlocks
	gc      *gc.Collector

	oidcMu sync.Mutex
	oidc   *webOIDC
}

// Options for New.
type Options struct {
	Clock     func() time.Time
	Logger    *slog.Logger
	Metrics   *metrics.Metrics
	LimiterIP *ratelimit.Limiter
	// Settings provides live runtime settings; may be nil.
	Settings interface {
		Effective() settings.Values
	}
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
		settings:    o.Settings,
	}
	if s.ipLimit == nil {
		s.ipLimit = ratelimit.New(50, 100, 1<<16, o.Clock)
	}
	if cfg.Web.Enabled {
		s.web = s.newWebUI()
		if s.web.pub == nil || s.web.pub.Scheme != "https" {
			if cfg.Web.CookieSecure != "always" && !isLoopback(cfg.Listen.Addr) &&
				cfg.Listen.TLS.Mode == "none" {
				s.Log.Warn("web cookies will not be Secure on a non-loopback listener")
			}
		}
	}
	s.blocks = &ipBlocks{denied: map[string]time.Time{}}
	if cfg.Audit.Enabled {
		s.auditor = NewAuditor(m, o.Clock)
		s.auditor.Start()
	}
	if cfg.Bandwidth.Enabled {
		s.bw = newBwManager(m, o.Clock)
		s.bw.met = o.Metrics
		s.bw.gUp.SetRate(cfg.Bandwidth.GlobalUpBps.Int64())
		s.bw.gDown.SetRate(cfg.Bandwidth.GlobalDownBps.Int64())
		s.bw.start()
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
	mux.HandleFunc("GET /v1/events", s.hEvents)
	mux.HandleFunc("GET /v1/admin/settings", s.hAdminSettingsGet)
	mux.HandleFunc("PATCH /v1/admin/settings", s.hAdminSettingsPatch)
	mux.HandleFunc("POST /v1/admin/users/{id}/ban", s.hAdminBan)
	mux.HandleFunc("POST /v1/admin/users/{id}/unban", s.hAdminUnban)
	mux.HandleFunc("POST /v1/admin/users/{id}/approve", s.hAdminApprove)
	mux.HandleFunc("POST /v1/admin/users/{id}/reject", s.hAdminReject)
	mux.HandleFunc("POST /v1/admin/users/{id}/password", s.hAdminSetPassword)
	mux.HandleFunc("GET /v1/admin/invites", s.hAdminInvites)
	mux.HandleFunc("POST /v1/admin/invites", s.hAdminInviteCreate)
	mux.HandleFunc("DELETE /v1/admin/invites/{id}", s.hAdminInviteDelete)
	mux.HandleFunc("GET /v1/admin/ip-blocks", s.hAdminBlocks)
	mux.HandleFunc("POST /v1/admin/ip-blocks", s.hAdminBlockCreate)
	mux.HandleFunc("DELETE /v1/admin/ip-blocks/{id}", s.hAdminBlockDelete)
	mux.HandleFunc("GET /v1/admin/audit", s.hAdminAudit)
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
	mux.HandleFunc("GET /v1/tokens/{id}", s.hTokenGet)
	mux.HandleFunc("PATCH /v1/tokens/{id}", s.hTokenPatch)
	mux.HandleFunc("GET /v1/tokens/{id}/events", s.hTokenEvents)
	mux.HandleFunc("GET /v1/tokens/{id}/stats", s.hTokenStats)
	return mux
}

var reqIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// requestID returns or mints one.
func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && reqIDRe.MatchString(id) {
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
	if !s.bwAttach(r, p, w) {
		return auth.Principal{}, false
	}
	return p, true
}

func (s *Server) clientIP(r *http.Request) string {
	return netx.IPPrefix(netx.ClientIPReal(r, s.trustedCIDRs(), s.Cfg.Proxy.RealIPHeader))
}

func (s *Server) trustedCIDRs() []netip.Prefix { return s.Cfg.TrustedProxyPrefixes() }

// siteVals returns the live site settings, falling back to config.
func (s *Server) siteVals() settings.Values {
	if s.settings != nil {
		return s.settings.Effective()
	}
	return settings.Defaults(s.Cfg)
}

// SetGC wires the GC for admin-triggered runs.
func (s *Server) SetGC(g *gc.Collector) { s.gc = g }

// CloseBandwidth flushes and stops the bandwidth manager when enabled.
func (s *Server) CloseBandwidth() {
	if s.bw != nil {
		s.bw.Close()
	}
}
