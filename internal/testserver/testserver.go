// SPDX-License-Identifier: 0BSD

// Package testserver spins up a real saves server in-process for
// client and server tests, on a mem blob and sqlite meta.
package testserver

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob/mem"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/Sudo-Ivan/saves/internal/quota"
	"github.com/Sudo-Ivan/saves/internal/server"
	"github.com/Sudo-Ivan/saves/internal/service"
)

// T is a running test server.
type T struct {
	Srv   *httptest.Server
	Meta  meta.Store
	Blob  *mem.Store
	Clock *testclock.Clock
}

// New starts a server bound to httptest with open quotas.
func New(t testing.TB) *T {
	t.Helper()
	c := testclock.New(time.Now())
	m, err := sqlite.Open(filepath.Join(t.TempDir(), "m.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := mem.New()
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	for k, t := range cfg.Quota.Tiers {
		t.Rate = config.RateLimit{RequestsPerSec: 0, Burst: 0}
		cfg.Quota.Tiers[k] = t
	}
	pol := config.AppPolicy{AllowForce: true}
	cfg.Quota.Apps = map[string]config.AppPolicy{"a": pol, "app": pol}
	cfg.Log.Access = false
	q := quota.New(&cfg)
	svc := service.New(m, b, q, service.Options{Clock: c.NowFunc(), MaxConcurrentUploadsPerUser: 64})
	chain := auth.Chain{&auth.TokenAuthenticator{Meta: m, Clock: c.NowFunc()}}
	reg := &auth.Registration{Mode: auth.RegOpen, Meta: m, DefaultTier: "free", Clock: c.NowFunc()}
	s := server.New(svc, m, b, chain, reg, &cfg, server.Options{Clock: c.NowFunc()})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	t.Cleanup(func() { m.Close() })
	return &T{Srv: srv, Meta: m, Blob: b, Clock: c}
}

// Token creates a user and returns a full token.
func (ts *T) Token(t testing.TB, subject string, scopes []string, apps []string) string {
	t.Helper()
	u, _, err := ts.Meta.UpsertUser(context.Background(), subject, "free")
	if err != nil {
		t.Fatal(err)
	}
	id, _, full, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Meta.CreateToken(context.Background(), meta.Token{
		ID: id, UserID: u.ID, SecretHash: hash, Scopes: scopes, Apps: apps,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return full
}
