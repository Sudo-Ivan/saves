// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"os"
	"runtime"
	"time"
)

// SysInfo describes the running process.
type SysInfo struct {
	Version      string
	Uptime       time.Duration
	GoVersion    string
	GOOS, GOARCH string
	Goroutines   int
	HeapAlloc    uint64
	HeapSys      uint64
	NumGC        uint32
	StartedAt    time.Time
	MetaDriver   string
	MetaDBBytes  int64
	BlobDriver   string
	Listener     string
	TLSMode      string
	Features     []string
	Overrides    int
}

// SysInfo builds a snapshot of process info.
func (s *Server) SysInfo() SysInfo {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	feat := []string{}
	if s.Cfg.Web.Enabled {
		feat = append(feat, "web")
	}
	if s.Cfg.Bandwidth.Enabled {
		feat = append(feat, "bandwidth")
	}
	if s.Cfg.Audit.Enabled {
		feat = append(feat, "audit")
	}
	if s.Cfg.Analytics.Enabled {
		feat = append(feat, "analytics")
	}
	feat = append(feat, "sandbox:"+s.Cfg.Sandbox.Mode)
	ov := 0
	return SysInfo{
		Version: s.Version, Uptime: time.Since(s.startedAt), StartedAt: s.startedAt,
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Goroutines: runtime.NumGoroutine(), HeapAlloc: m.HeapAlloc, HeapSys: m.HeapSys,
		NumGC: m.NumGC, MetaDriver: s.Cfg.Storage.Meta.Driver, BlobDriver: s.Cfg.Storage.Blob.Driver,
		Listener: s.Cfg.Listen.Addr, TLSMode: s.Cfg.Listen.TLS.Mode,
		Features: feat, Overrides: ov,
	}
}

// Finding is one security checkup item.
type Finding struct {
	ID       string
	Severity string
	Title    string
	Detail   string
	Fix      string
}

// SecurityCheckup evaluates config against hardening rules.
func (s *Server) SecurityCheckup(ctx context.Context) []Finding {
	c := s.Cfg
	var out []Finding
	add := func(id, sev, title, detail, fix string) {
		out = append(out, Finding{ID: id, Severity: sev, Title: title, Detail: detail, Fix: fix})
	}
	if c.Listen.TLS.Mode == "none" && !isLoopback(c.Listen.Addr) {
		add("tls_none", "critical", "TLS disabled on a public listener", "plain HTTP serves tokens", "enable TLS or set public_url https")
	}
	if c.Web.CookieSecure == "never" || (c.Web.CookieSecure != "always" && c.Listen.TLS.Mode == "none") {
		add("cookies", "warn", "Cookies may not be Secure", "session cookies could ride HTTP", "set web.cookie_secure always")
	}
	if c.Registration.Mode == "open" && !c.Registration.RequireApproval {
		add("reg_open", "warn", "Open registration without approval", "anyone can sign up", "set registration.require_approval or use invite mode")
	}
	if c.Web.Secret != "" && len(c.Web.Secret) < 48 {
		add("secret", "critical", "web.secret too short", "session secret under 48 chars", "use a 64 char secret")
	}
	if c.Sandbox.Mode != "enforce" {
		add("sandbox", "warn", "Sandbox not enforcing", "mode "+c.Sandbox.Mode, "set sandbox.mode enforce")
	}
	if c.CORS.Enabled {
		add("cors", "warn", "CORS enabled", "cross origin browsers can call the API", "keep CORS off unless needed")
	}
	if !isLoopback(c.Ops.Addr) && c.Ops.Enabled {
		add("ops", "warn", "Ops listener exposed", "non loopback ops address", "bind ops to loopback")
	}
	if c.Auth.Anonymous.Enabled {
		add("anon", "warn", "Anonymous auth enabled", "unauthenticated requests allowed", "disable anonymous")
	}
	if !c.Web.HSTS.Enabled && c.Listen.TLS.Mode != "none" {
		add("hsts", "info", "HSTS disabled", "https without strict transport", "enable hsts")
	}
	if !c.Audit.Enabled {
		add("audit", "warn", "Audit disabled", "admin actions unlogged", "enable audit")
	}
	if !c.Analytics.Enabled {
		add("analytics", "info", "Analytics disabled", "usage stats off", "enable analytics")
	}
	if c.Quota.Tiers[c.Quota.DefaultTier].QuotaBytes == 0 && c.Registration.Mode == "open" {
		add("quota", "warn", "Unlimited default tier with open registration", "new users get no quota", "set a quota on the default tier")
	}
	if sv := s.siteVals(); sv.Maintenance {
		add("maintenance", "info", "Maintenance mode on", sv.MaintenanceMsg, "")
	}
	return out
}

var _ = os.Stat
