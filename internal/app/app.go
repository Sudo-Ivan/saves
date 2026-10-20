// SPDX-License-Identifier: 0BSD

// Package app is the savesd subcommand dispatcher and serve runtime.
// Phase 4b registers init, admin, fsck and sandbox-check here.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"log/slog"

	"database/sql"
	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/blob/fs"
	"github.com/Sudo-Ivan/saves/internal/blob/s3"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/gc"
	"github.com/Sudo-Ivan/saves/internal/meta"
	_ "github.com/Sudo-Ivan/saves/internal/meta/all"
	"github.com/Sudo-Ivan/saves/internal/metrics"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/quota"
	"github.com/Sudo-Ivan/saves/internal/sandbox"
	"github.com/Sudo-Ivan/saves/internal/server"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/prometheus/client_golang/prometheus"
	"strings"
)

// Version is the build version.
var Version = "dev"

// Run dispatches argv[1:].
func Run(argv []string) int {
	if len(argv) == 0 {
		argv = []string{"serve"}
	}
	var cmd, rest string
	cmd, rest = argv[0], ""
	args := argv[1:]
	_ = rest
	switch cmd {
	case "init":
		return cmdInit(args)
	case "admin":
		return cmdAdmin(args)
	case "sandbox-check":
		return cmdSandboxCheck(argv[1:])
	case "serve":
		return cmdServe(args)
	case "config":
		return cmdConfig(args)
	case "migrate":
		return cmdMigrate(args)
	case "fsck":
		return cmdFsck(args)
	case "gc":
		return cmdGC(args)
	case "backup-meta":
		return cmdBackupMeta(args)
	case "healthcheck":
		return cmdHealthcheck(args)
	case "version":
		fmt.Println("savesd", Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "savesd: unknown command %q\n", cmd)
		return 2
	}
}

func configPath(args []string) string {
	for i, a := range args {
		if (a == "-c" || a == "-config" || a == "--config") && i+1 < len(args) {
			return args[i+1]
		}
		if len(a) > 7 && a[:7] == "--conf=" {
			return a[7:]
		}
		if len(a) > 9 && a[:9] == "--config=" {
			return a[9:]
		}
	}
	if v := os.Getenv("SAVES_CONFIG"); v != "" {
		return v
	}
	return "saves.json"
}

func cmdConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: savesd config check|print-defaults")
		return 2
	}
	switch args[0] {
	case "check":
		if _, err := config.Load(configPath(args[1:])); err != nil {
			fmt.Fprintln(os.Stderr, "config error:", err)
			return 1
		}
		if warn := config.ModeWarning(configPath(args[1:])); warn != "" {
			fmt.Fprintln(os.Stderr, "warning:", warn)
		}
		fmt.Println("config ok")
		return 0
	case "print-defaults":
		out, err := json.MarshalIndent(config.Defaults(), "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(string(out))
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: savesd config check|print-defaults")
	return 2
}

func cmdHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:9090/healthz", "health endpoint")
	to := fs.Duration("timeout", 3*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := &http.Client{Transport: netx.NewTransport(), Timeout: *to}
	resp, err := c.Get(*url)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func cmdMigrate(args []string) int {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 1
	}
	m, err := openMeta(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meta error:", err)
		return 1
	}
	defer m.Close()
	if err := m.Migrate(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "migrate error:", err)
		return 1
	}
	fmt.Println("migrated")
	return 0
}

func openMeta(cfg *config.Config) (meta.Store, error) {
	mc := cfg.Storage.Meta
	switch mc.Driver {
	case "sqlite", "":
		return meta.Open(context.Background(), "sqlite", mc.SQLite.Path, meta.Options{})
	case "postgres":
		return meta.Open(context.Background(), "postgres", mc.Postgres.DSN, meta.Options{})
	}
	return nil, fmt.Errorf("app: unknown meta driver %q", mc.Driver)
}

func openBlob(cfg *config.Config) (blob.Store, error) {
	switch cfg.Storage.Blob.Driver {
	case "fs", "":
		return fs.New(fs.Options{Root: cfg.Storage.Blob.FS.Root, Fsync: cfg.Storage.Blob.FS.Fsync})
	case "s3":
		c := cfg.Storage.Blob.S3
		return s3.New(s3.Options{
			Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket, Prefix: c.Prefix,
			AccessKey: c.AccessKey, SecretKey: c.SecretKey, PathStyle: c.PathStyle,
			Insecure: c.Insecure, RequestTimeout: c.RequestTimeout.Duration(), MaxRetries: c.MaxRetries,
		})
	}
	return nil, fmt.Errorf("app: unknown blob driver %q", cfg.Storage.Blob.Driver)
}

// applySandbox is the phase 4b hook. It is intentionally a no-op until
// the sandbox lands; it sits between resource open and serve.
func cmdFsck(args []string) int {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return 1
	}
	repair := false
	for _, a := range args {
		repair = repair || a == "-repair"
	}
	st, err := openStore(cfg)
	if err != nil {
		return 1
	}
	defer st.Close()
	rep, err := st.Fsck(context.Background(), repair)
	if err != nil {
		return 1
	}
	if len(rep.Issues) == 0 {
		fmt.Println("fsck: clean")
	}
	for _, i := range rep.Issues {
		fmt.Println("fsck:", i)
	}
	if rep.Repaired {
		fmt.Println("fsck: repaired")
	}
	return 0
}

func cmdGC(args []string) int {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return 1
	}
	st, err := openStore(cfg)
	if err != nil {
		return 1
	}
	defer st.Close()
	b, err := openBlob(cfg)
	if err != nil {
		return 1
	}
	defer b.Close()
	g := gc.New(st, b, gc.Options{})
	rep, err := g.RunOnce(context.Background())
	if err != nil {
		return 1
	}
	fmt.Println("gc:", rep)
	return 0
}

func cmdBackupMeta(args []string) int {
	var out string
	for i, a := range args {
		if a == "-out" && i+1 < len(args) {
			out = args[i+1]
		}
	}
	if out == "" {
		return 2
	}
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return 1
	}
	if cfg.Storage.Meta.Driver != "sqlite" {
		fmt.Fprintln(os.Stderr, "backup-meta: sqlite only; use pg_dump for postgres")
		return 1
	}
	db, err := sql.Open("sqlite", cfg.Storage.Meta.SQLite.Path)
	if err != nil {
		return 1
	}
	defer db.Close()
	if _, err := db.ExecContext(context.Background(),
		"VACUUM INTO '"+strings.ReplaceAll(out, "'", "''")+"'"); err != nil {
		fmt.Fprintln(os.Stderr, "backup-meta:", err)
		return 1
	}
	fmt.Println("backup-meta:", out)
	return 0
}

func cmdSandboxCheck(args []string) int {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 1
	}
	pol, err := sandbox.FromConfig(cfg, configPath(args))
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy error:", err)
		return 1
	}
	if os.Getenv("SAVES_SBX_CHILD") == "1" {
		return sandbox.Child(pol, cfg.Sandbox.Mode)
	}
	cmd := exec.Command(os.Args[0], "sandbox-check")
	cmd.Args = append(cmd.Args, args...)
	cmd.Env = append(os.Environ(), "SAVES_SBX_CHILD=1")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return 1
	}
	return 0
}

func applySandbox(cfg *config.Config, reg *prometheus.Registry) error {
	if err := sandbox.Harden(cfg.Sandbox.AllowRoot); err != nil {
		return err
	}
	pol, err := sandbox.FromConfig(cfg, configPath(os.Args[1:]))
	if err != nil {
		return err
	}
	rep, err := sandbox.Apply(pol, cfg.Sandbox.Mode)
	if err != nil {
		return err
	}
	if cfg.Sandbox.Mode == "off" {
		slog.Warn("sandbox disabled")
	} else {
		slog.Info("sandbox", "abi", rep.ABI, "fs", rep.FS, "tcp", rep.TCP, "scoped", rep.Scoped, "mode", rep.Mode)
		if reg != nil {
			sandbox.ReportMetrics(reg, rep)
		}
	}
	return nil
}

func cmdServe(args []string) int {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 1
	}
	var logger *slog.Logger
	if cfg.Log.Format == "json" {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level(cfg.Log.Level)}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level(cfg.Log.Level)}))
	}
	slog.SetDefault(logger)

	met := metrics.New(cfg.Metrics.Namespace, Version)
	m0, err := openMeta(cfg)
	if err != nil {
		logger.Error("meta open", "err", err)
		return 1
	}
	defer m0.Close()
	m := metrics.WrapMeta(m0, met.Reg, cfg.Metrics.Namespace)
	if err := m.Migrate(context.Background()); err != nil {
		logger.Error("migrate", "err", err)
		return 1
	}
	b0, err := openBlob(cfg)
	if err != nil {
		logger.Error("blob open", "err", err)
		return 1
	}
	b := metrics.WrapBlob(b0, met.Reg, cfg.Metrics.Namespace)

	q := quota.New(cfg)
	svc := service.New(m, b, q, service.Options{
		Clock:                       time.Now,
		Metrics:                     met,
		MaxConcurrentUploads:        cfg.Limits.MaxConcurrentUploads,
		MaxConcurrentUploadsPerUser: 4,
	})
	chain, reg, err := buildAuth(cfg, m)
	for _, a := range chain {
		if ta, ok := a.(*auth.TokenAuthenticator); ok {
			svc.TokenInvalidator = ta.Invalidate
		}
	}
	if err != nil {
		logger.Error("auth", "err", err)
		return 1
	}
	srv := server.New(svc, m, b, chain, reg, cfg, server.Options{Logger: logger, Metrics: met})
	runner := server.NewRunner(srv, cfg)
	logVar := &slog.LevelVar{}
	_ = logVar
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Sandbox hook before serving (4b).
	if err := applySandbox(cfg, met.Reg); err != nil {
		logger.Error("sandbox", "err", err)
		return 1
	}
	if err := runner.Listen(ctx); err != nil {
		logger.Error("listen", "err", err)
		return 1
	}
	// GC loop.
	gcCtx, gcStop := context.WithCancel(ctx)
	defer gcStop()
	go gc.New(m, b, gc.Options{
		Holder: cfg.GC.LeaseHolder, Interval: cfg.GC.Interval.Duration(),
		Grace: cfg.GC.GracePeriod.Duration(), BatchSize: cfg.GC.BatchSize,
	}).Run(gcCtx)

	// Ops listener.
	if cfg.Ops.Enabled {
		opsrv := &http.Server{ // #nosec G112 -- ops listener is loopback only
			Addr:              cfg.Ops.Addr,
			Handler:           srv.OpsMux(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() { _ = opsrv.ListenAndServe() }()
		defer opsrv.Close()
	}
	// SIGHUP: re-read config, apply reloadable subset, reload cert.
	rel := &reloader{path: configPath(args), logger: logger, quota: q, runner: runner, old: cfg}
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				rel.reload()
			}
		}
	}()
	logger.Info("serving", "addr", cfg.Listen.Addr)
	if err := runner.Serve(ctx); err != nil {
		logger.Error("serve", "err", err)
		return 1
	}
	return 0
}

func level(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func buildAuth(cfg *config.Config, m meta.Store) (auth.Chain, *auth.Registration, error) {
	var chain auth.Chain
	for _, name := range cfg.Auth.Order {
		switch name {
		case "token":
			if cfg.Auth.Token.Enabled {
				ta := &auth.TokenAuthenticator{
					Meta: m, TouchTTL: cfg.Auth.Token.LastUsedInterval.Duration(),
					CacheTTL: cfg.Auth.Token.CacheTTL.Duration(),
				}
				chain = append(chain, ta)
			}
		case "proxy":
			if cfg.Auth.Proxy.Enabled {
				var cidrs []netip.Prefix
				for _, c := range cfg.Auth.Proxy.TrustedCIDRs {
					p, err := netip.ParsePrefix(c)
					if err != nil {
						return nil, nil, fmt.Errorf("proxy cidr %q: %w", c, err)
					}
					cidrs = append(cidrs, p)
				}
				chain = append(chain, &auth.ProxyAuthenticator{
					Trusted: cidrs, Meta: m, SubjectHdr: cfg.Auth.Proxy.Header,
					AutoProvision: true, DefaultTier: cfg.Quota.DefaultTier,
				})
			}
		case "anonymous":
			if cfg.Auth.Anonymous.Enabled {
				sc, err := auth.ParseScopes(join(cfg.Auth.Anonymous.Scopes))
				if err != nil {
					return nil, nil, err
				}
				chain = append(chain, &auth.AnonymousAuthenticator{
					Secret: []byte(cfg.Auth.IPSecret), Scopes: sc, Tier: cfg.Quota.AnonymousTier, Meta: m,
				})
			}
		case "oidc":
			if cfg.Auth.OIDC.Enabled {
				a, err := auth.NewOIDC(m, auth.OIDCConfig{
					Issuer: cfg.Auth.OIDC.Issuer, Audience: cfg.Auth.OIDC.Audience,
					Algs: cfg.Auth.OIDC.Algs, AutoProvision: cfg.Auth.OIDC.AutoProvision,
					DefaultTier: cfg.Quota.DefaultTier, ClockSkew: cfg.Auth.OIDC.ClockSkew.Duration(),
					ScopeClaim: cfg.Auth.OIDC.ScopeClaim,
				})
				if err != nil {
					return nil, nil, err
				}
				chain = append(chain, a)
			}
		}
	}
	var reg *auth.Registration
	switch cfg.Registration.Mode {
	case "invite":
		reg = &auth.Registration{Mode: auth.RegInvite, Meta: m, DefaultTier: cfg.Quota.DefaultTier,
			Invites: map[string]*auth.Invite{}}
		for _, c := range cfg.Registration.InviteCodes {
			reg.Invites[c] = &auth.Invite{Code: c, MaxUses: cfg.Registration.InviteMaxUses}
		}
	case "open":
		reg = &auth.Registration{Mode: auth.RegOpen, Meta: m, DefaultTier: cfg.Quota.DefaultTier}
	}
	return chain, reg, nil
}

func join(v []string) string {
	s := ""
	for i, x := range v {
		if i > 0 {
			s += ","
		}
		s += x
	}
	return s
}

var _ = errors.New

// reloader owns SIGHUP config reload state for testability.
type reloader struct {
	path   string
	logger *slog.Logger
	quota  *quota.Resolver
	logVar *slog.LevelVar
	runner *server.Runner
	old    *config.Config
}

// reload re-reads and validates the config, applies the reloadable
// subset, and reports which keys changed.
func (r *reloader) reload() {
	cfg, err := config.Load(r.path)
	if err != nil {
		r.logger.Warn("config reload failed, keeping old", "err", err)
		return
	}
	reloadable := config.DiffReloadable(*r.old, *cfg)
	if len(reloadable) > 0 {
		r.quota.Reload(cfg)
		if r.logVar != nil {
			r.logVar.Set(level(cfg.Log.Level))
		}
		r.logger.Info("config reloaded", "keys", reloadable)
	}
	all := config.Diff(*r.old, *cfg)
	var restart []string
	for _, k := range all {
		isR := false
		for _, rk := range reloadable {
			if rk == k {
				isR = true
			}
		}
		if !isR {
			restart = append(restart, k)
		}
	}
	if len(restart) > 0 {
		r.logger.Warn("config changed but needs restart", "keys", restart)
	}
	if err := r.runner.ReloadCert(); err != nil {
		r.logger.Warn("cert reload", "err", err)
	}
	r.old = cfg
}
