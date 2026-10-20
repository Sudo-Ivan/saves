// SPDX-License-Identifier: 0BSD

// Package hub runs an embedded saves node in-process so a device can
// act as the sync host for paired peers over the QUIC transport.
package hub

import (
	"context"
	"net/http"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/blob/fs"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/events"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/internal/quota"
	"github.com/Sudo-Ivan/saves/internal/server"
	"github.com/Sudo-Ivan/saves/internal/service"
)

// Options for Start.
type Options struct {
	Dir  string
	Name string
}

// Hub is the embedded node.
type Hub struct {
	handler http.Handler
	meta    meta.Store
	blob    blob.Store
	svc     *service.Service
}

// Start builds the stack: sqlite at Dir/meta.db, fs blobs at Dir/blobs.
func Start(ctx context.Context, o Options) (*Hub, error) {
	cfg := config.Defaults()
	cfg.Storage.Meta.Driver = "sqlite"
	cfg.Storage.Meta.SQLite.Path = o.Dir + "/meta.db"
	cfg.Storage.Blob.Driver = "fs"
	cfg.Storage.Blob.FS.Root = o.Dir + "/blobs"
	m, err := sqlite.Open(o.Dir+"/meta.db", meta.Options{Clock: time.Now})
	if err != nil {
		return nil, err
	}
	if err := m.Migrate(ctx); err != nil {
		m.Close()
		return nil, err
	}
	b, err := fs.New(fs.Options{Root: o.Dir + "/blobs"})
	if err != nil {
		m.Close()
		return nil, err
	}
	dev := cfg.Quota.Tiers["free"]
	dev.QuotaBytes = config.Size(1 << 40)
	dev.MaxSlots = 4096
	dev.MaxPendingSnapshots = 16
	dev.MaxConcurrentUploads = 16
	dev.Rate = config.RateLimit{}
	cfg.Quota.Tiers["device"] = dev
	cfg.Quota.DefaultTier = "device"
	cfg.Quota.AllowUnknownApps = ".*"
	q := quota.New(&cfg)
	svc := service.New(m, b, q, service.Options{Clock: time.Now,
		MaxConcurrentUploads:        cfg.Limits.MaxConcurrentUploads,
		MaxConcurrentUploadsPerUser: 4})
	svc.Events = events.New(cfg.Limits.MaxEventStreams, 64)
	ta := &auth.TokenAuthenticator{Meta: m, Clock: time.Now}
	svc.TokenInvalidator = ta.Invalidate
	reg := &auth.Registration{Meta: m, Clock: time.Now}
	srv := server.New(svc, m, b, auth.Chain{ta}, reg, &cfg,
		server.Options{Clock: time.Now})
	return &Hub{handler: srv.Handler(), meta: m, blob: b, svc: svc}, nil
}

// Handler serves the saves API.
func (h *Hub) Handler() http.Handler { return h.handler }

// MintToken issues an sv1_ token for the owner user (same shape as
// savesd admin token create: tid + base64url secret, sha256 secret hash).
func (h *Hub) MintToken(ctx context.Context, name string, scopes []string) (string, error) {
	u, _, err := h.meta.UpsertUser(ctx, "owner", "device")
	if err != nil {
		return "", err
	}
	tid, _, full, hash, err := auth.GenerateToken()
	if err != nil {
		return "", err
	}
	if err := h.meta.CreateToken(ctx, meta.Token{
		ID: tid, UserID: u.ID, SecretHash: hash,
		Name: name, Scopes: scopes, CreatedAt: time.Now(),
	}); err != nil {
		return "", err
	}
	return full, nil
}

// ListTokens returns the owner's tokens.
func (h *Hub) ListTokens(ctx context.Context) ([]meta.Token, error) {
	u, _, err := h.meta.UpsertUser(ctx, "owner", "device")
	if err != nil {
		return nil, err
	}
	return h.meta.ListTokens(ctx, u.ID)
}

// RevokeToken revokes by token id.
func (h *Hub) RevokeToken(ctx context.Context, id string) error {
	return h.meta.RevokeToken(ctx, id)
}

// Close shuts resources.
func (h *Hub) Close() error { h.blob.Close(); return h.meta.Close() }
