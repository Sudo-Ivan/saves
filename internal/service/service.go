// SPDX-License-Identifier: 0BSD

// Package service is the HTTP-agnostic core: it wires the metadata
// store, blob store, quota resolver, clock, and metrics into the
// snapshot write and read paths used by the handlers.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/chunkindex"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/quota"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Metrics receives operation counters; the zero value does nothing.
type Metrics interface {
	Observe(op string, err error, d time.Duration)
}

// NopMetrics is the default no-op metrics.
type NopMetrics struct{}

// Observe implements Metrics.
func (NopMetrics) Observe(string, error, time.Duration) {}

// Logger is the minimal sink.
type Logger interface {
	Errorf(format string, args ...any)
}

// Service is the business core.
type Service struct {
	Meta    meta.Store
	Blob    blob.Store
	Quota   *quota.Resolver
	Clock   func() time.Time
	Metrics Metrics
	Log     Logger

	// TokenInvalidator drops a cached token validation on the local
	// auth cache after revocation.
	TokenInvalidator func(id string)

	manCache *manifestCache

	// ManifestCacheBytes bounds the decoded manifest LRU; 0 disables.
	ManifestCacheBytes int64

	// Global and per-user concurrent upload caps.
	globalSem chan struct{}
	userSems  sync.Map // userID -> chan struct{}
	maxUserUp int
}

// Options configures Service.
type Options struct {
	Clock                       func() time.Time
	Metrics                     Metrics
	Log                         Logger
	MaxConcurrentUploads        int // global
	MaxConcurrentUploadsPerUser int
}

// New wires a service.
func New(m meta.Store, b blob.Store, q *quota.Resolver, o Options) *Service {
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Metrics == nil {
		o.Metrics = NopMetrics{}
	}
	if o.MaxConcurrentUploads <= 0 {
		o.MaxConcurrentUploads = 64
	}
	if o.MaxConcurrentUploadsPerUser <= 0 {
		o.MaxConcurrentUploadsPerUser = 4
	}
	return &Service{
		Meta: m, Blob: b, Quota: q, Clock: o.Clock, Metrics: o.Metrics, Log: o.Log,
		globalSem: make(chan struct{}, o.MaxConcurrentUploads),
		maxUserUp: o.MaxConcurrentUploadsPerUser,
	}
}

func (s *Service) now() time.Time { return s.Clock() }

var ErrLatestAmbiguous = errors.New("service: no committed snapshot")
var ErrTooLarge = errors.New("service: too large")
var ErrUploadBusy = errors.New("service: too many concurrent uploads")

// requireScope enforces scope bits and app allowlist.
func requireScope(p auth.Principal, need auth.Scope, app string) error {
	if p.Scopes&need != need {
		return &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	if len(p.Apps) > 0 {
		for _, a := range p.Apps {
			if a == app {
				return nil
			}
		}
		return &api.Problem{Code: api.CodeForbidden, Title: "app not allowed", Status: 403}
	}
	return nil
}

func (s *Service) eff(p auth.Principal, app string) (quota.Effective, error) {
	return s.Quota.For(p.User, app, p.Anonymous)
}

// mapErr converts meta errors to api.Problem.
func mapErr(err error) error {
	var qe *meta.QuotaError
	var ce *meta.ConflictError
	var ie *meta.IncompleteError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, meta.ErrNotFound):
		return &api.Problem{Code: api.CodeNotFound, Title: "not found", Status: 404}
	case errors.Is(err, meta.ErrDisabled):
		return &api.Problem{Code: api.CodeForbidden, Title: "disabled", Status: 403}
	case errors.As(err, &qe):
		return &api.Problem{Code: api.CodeQuotaExceeded, Title: "quota exceeded", Status: 429, Detail: qe.Error()}
	case errors.As(err, &ce):
		return &api.Problem{Code: api.CodeConflict, Title: "head conflict", Status: 409}
	case errors.As(err, &ie):
		return &api.Problem{Code: api.CodeInvalidManifest, Title: "incomplete upload", Status: 422}
	case errors.Is(err, meta.ErrPendingLimit), errors.Is(err, meta.ErrSlotLimit):
		return &api.Problem{Code: api.CodeConflict, Title: "limit reached", Status: 409}
	case errors.Is(err, ErrUploadBusy):
		return &api.Problem{Code: api.CodeRateLimited, Title: "busy", Status: 429}
	default:
		return err
	}
}

// Me returns the caller identity and usage.
func (s *Service) Me(ctx context.Context, p auth.Principal) (meta.User, meta.Usage, error) {
	u, err := s.Meta.Usage(ctx, p.User.ID)
	return p.User, u, mapErr(err)
}

// ListApps lists the caller's apps.
func (s *Service) ListApps(ctx context.Context, p auth.Principal) ([]meta.AppSummary, error) {
	if err := requireScope(p, auth.ScopeRead, ""); err != nil {
		return nil, err
	}
	out, err := s.Meta.ListApps(ctx, p.User.ID)
	return out, mapErr(err)
}

// ListSlots lists slots of an app.
func (s *Service) ListSlots(ctx context.Context, p auth.Principal, app string) ([]meta.Slot, error) {
	if err := requireScope(p, auth.ScopeRead, app); err != nil {
		return nil, err
	}
	out, err := s.Meta.ListSlots(ctx, p.User.ID, app)
	return out, mapErr(err)
}

// GetSlot returns one slot.
func (s *Service) GetSlot(ctx context.Context, p auth.Principal, app, slot string) (meta.Slot, error) {
	if err := requireScope(p, auth.ScopeRead, app); err != nil {
		return meta.Slot{}, err
	}
	out, err := s.Meta.GetSlot(ctx, p.User.ID, app, slot)
	return out, mapErr(err)
}

// DeleteSlot deletes a slot and releases its references.
func (s *Service) DeleteSlot(ctx context.Context, p auth.Principal, app, slot string) error {
	if err := requireScope(p, auth.ScopeWrite, app); err != nil {
		return err
	}
	return mapErr(s.Meta.DeleteSlot(ctx, p.User.ID, app, slot))
}

// BeginOut is returned by BeginSnapshot.
type BeginOut struct {
	ID        string
	Missing   []api.Hash
	ExpiresAt *time.Time
}

// BeginSnapshot validates and stores the manifest blob, then begins.
func (s *Service) BeginSnapshot(ctx context.Context, p auth.Principal, app, slot, device, label, expectedHead string, m api.Manifest) (BeginOut, error) {
	var out BeginOut
	if err := requireScope(p, auth.ScopeWrite, app); err != nil {
		return out, err
	}
	eff, err := s.eff(p, app)
	if err != nil {
		return out, mapErr(meta.ErrNotFound)
	}
	if err := m.Validate(eff.APILimits); err != nil {
		return out, &api.Problem{Code: api.CodeInvalidManifest, Title: "invalid manifest", Status: 422, Detail: err.Error()}
	}
	// Manifest content bytes.
	canon, mh, err := m.Canonical()
	if err != nil {
		return out, err
	}
	// Store manifest blob before Begin returns, content addressed.
	if err := s.Blob.Put(ctx, blob.ManifestKey(p.User.ID, mh), bytesReader(canon), int64(len(canon)), &mh); err != nil {
		return out, err
	}
	var total int64
	seen := map[api.Hash]bool{}
	var uniq []api.ChunkRef
	for _, f := range m.Files {
		for _, c := range f.Chunks {
			total += int64(c.Size)
			if !seen[c.Hash] {
				seen[c.Hash] = true
				uniq = append(uniq, c)
			}
		}
	}
	exp := s.now().Add(24 * time.Hour)
	res, err := s.Meta.BeginSnapshot(ctx, meta.BeginParams{
		UserID: p.User.ID, App: app, Slot: slot, ParentID: expectedHead,
		Device: device, Label: label,
		ManifestHash: mh, ManifestSize: int64(len(canon)),
		TotalBytes: total, FileCount: len(m.Files),
		Chunks: uniq,
		Limits: meta.BeginLimits{
			QuotaBytes: eff.QuotaBytes, MaxSlots: eff.MaxSlots,
			MaxPendingSnapshots: eff.MaxPendingSnapshots, ExpiresAt: exp,
		},
	})
	if err != nil {
		return out, mapErr(err)
	}
	out.ID = res.Snapshot.ID
	out.Missing = res.Missing
	out.ExpiresAt = res.Snapshot.ExpiresAt
	return out, nil
}

func bytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}

// PutChunk stores one missing chunk.
func (s *Service) PutChunk(ctx context.Context, p auth.Principal, app, slot, snapshotID string, h api.Hash, body io.Reader, size int64) error {
	if err := requireScope(p, auth.ScopeWrite, app); err != nil {
		return err
	}
	eff, err := s.eff(p, app)
	if err != nil {
		return mapErr(meta.ErrNotFound)
	}
	if eff.APILimits.MaxChunkBytes > 0 && size > eff.APILimits.MaxChunkBytes {
		return &api.Problem{Code: api.CodeTooLarge, Title: "chunk too large", Status: 413}
	}
	if size < 0 {
		return &api.Problem{Code: api.CodeBadRequest, Title: "bad size", Status: 400}
	}
	// Caps.
	select {
	case s.globalSem <- struct{}{}:
		defer func() { <-s.globalSem }()
	default:
		return mapErr(ErrUploadBusy)
	}
	v, _ := s.userSems.LoadOrStore(p.User.ID, make(chan struct{}, s.maxUserUp))
	sem := v.(chan struct{})
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		return mapErr(ErrUploadBusy)
	}
	key := blob.ChunkKey(p.User.ID, h)
	if err := s.Blob.Put(ctx, key, body, size, &h); err != nil {
		return err
	}
	return mapErr(s.Meta.MarkChunkStored(ctx, p.User.ID, snapshotID, h, size))
}

// CommitSnapshot commits with CAS and retention.
func (s *Service) CommitSnapshot(ctx context.Context, p auth.Principal, app, slot, id, expectedHead string, force bool) (meta.CommitResult, error) {
	var res meta.CommitResult
	if err := requireScope(p, auth.ScopeWrite, app); err != nil {
		return res, err
	}
	eff, err := s.eff(p, app)
	if err != nil {
		return res, mapErr(meta.ErrNotFound)
	}
	if force && !eff.AllowForce {
		force = false
	}
	res, err = s.Meta.CommitSnapshot(ctx, p.User.ID, id, meta.CommitOptions{
		ExpectedHead: expectedHead, Force: force,
		KeepLast: eff.KeepLast, MaxAge: time.Duration(eff.MaxAge),
	})
	return res, mapErr(err)
}

// DeleteSnapshot deletes a non-head snapshot.
func (s *Service) DeleteSnapshot(ctx context.Context, p auth.Principal, app, slot, id string) error {
	if err := requireScope(p, auth.ScopeWrite, app); err != nil {
		return err
	}
	return mapErr(s.Meta.DeleteSnapshot(ctx, p.User.ID, app, slot, id))
}

// ListSnapshots pages snapshots, resolving "latest" for id params elsewhere.
func (s *Service) ListSnapshots(ctx context.Context, p auth.Principal, app, slot, cursor string, limit int) ([]meta.Snapshot, string, error) {
	if err := requireScope(p, auth.ScopeRead, app); err != nil {
		return nil, "", err
	}
	out, next, err := s.Meta.ListSnapshots(ctx, p.User.ID, app, slot, cursor, limit)
	return out, next, mapErr(err)
}

// ResolveSnapshot resolves an id or the alias "latest" to a snapshot.
func (s *Service) ResolveSnapshot(ctx context.Context, p auth.Principal, app, slot, id string) (meta.Snapshot, error) {
	if err := requireScope(p, auth.ScopeRead, app); err != nil {
		return meta.Snapshot{}, err
	}
	if id == "latest" {
		sl, err := s.Meta.GetSlot(ctx, p.User.ID, app, slot)
		if err != nil {
			return meta.Snapshot{}, mapErr(err)
		}
		if sl.HeadSnapshotID == "" {
			return meta.Snapshot{}, mapErr(meta.ErrNotFound)
		}
		id = sl.HeadSnapshotID
	}
	sn, err := s.Meta.GetSnapshot(ctx, p.User.ID, app, slot, id)
	return sn, mapErr(err)
}

// GetManifest returns manifest bytes for a snapshot.
func (s *Service) GetManifest(ctx context.Context, p auth.Principal, app, slot, id string) ([]byte, api.Hash, error) {
	sn, err := s.ResolveSnapshot(ctx, p, app, slot, id)
	if err != nil {
		return nil, api.Hash{}, err
	}
	b, err := s.readManifest(ctx, p.User.ID, sn.ManifestHash)
	if err != nil {
		return nil, api.Hash{}, err
	}
	return b, sn.ManifestHash, nil
}

// readManifest returns raw manifest bytes, populating the decoded
// manifest cache keyed by (user, hash).
func (s *Service) readManifest(ctx context.Context, userID string, h api.Hash) ([]byte, error) {
	o, err := s.Blob.Open(ctx, blob.ManifestKey(userID, h))
	if err != nil {
		return nil, mapErr(meta.ErrNotFound)
	}
	defer o.Close()
	b, err := io.ReadAll(io.NewSectionReader(o, 0, o.Size()))
	if err != nil {
		return nil, err
	}
	if s.manCache != nil {
		if m, derr := api.DecodeManifest(bytes.NewReader(b), int64(len(b))+1); derr == nil {
			s.manCache.put(userID, h, *m, b)
		}
	}
	return b, nil
}

// decodedManifest returns a decoded manifest from cache or blob.
func (s *Service) decodedManifest(ctx context.Context, userID string, h api.Hash) (*api.Manifest, error) {
	if m, _, ok := s.manCache.get(userID, h); ok {
		return &m, nil
	}
	b, err := s.readManifest(ctx, userID, h)
	if err != nil {
		return nil, err
	}
	if m, _, ok := s.manCache.get(userID, h); ok {
		return &m, nil
	}
	m, err := api.DecodeManifest(bytes.NewReader(b), int64(len(b))+1)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// FileHandle is a seekable open file.
type FileHandle struct {
	Reader  io.ReadSeeker
	Size    int64
	ModTime time.Time
	ETag    string
}

// OpenFile opens a file inside a snapshot for range reads.
func (s *Service) OpenFile(ctx context.Context, p auth.Principal, app, slot, id, path string) (*FileHandle, error) {
	sn, err := s.ResolveSnapshot(ctx, p, app, slot, id)
	if err != nil {
		return nil, err
	}
	m, err := s.decodedManifest(ctx, p.User.ID, sn.ManifestHash)
	if err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		if f.Path != path {
			continue
		}
		if f.Inline != nil {
			return &FileHandle{
				Reader:  bytes.NewReader(f.Inline),
				Size:    int64(len(f.Inline)),
				ModTime: time.Unix(0, f.ModTimeNS),
				ETag:    fmt.Sprintf(`"%x"`, api.HashBytes(f.Inline)),
			}, nil
		}
		open := func(h api.Hash) (blob.Object, error) {
			return s.Blob.Open(ctx, blob.ChunkKey(p.User.ID, h))
		}
		r, err := chunkindex.New(f.Chunks, f.Size, open)
		if err != nil {
			return nil, err
		}
		return &FileHandle{
			Reader:  r,
			Size:    int64(f.Size),
			ModTime: time.Unix(0, f.ModTimeNS),
			ETag:    fmt.Sprintf(`"%x"`, sn.ManifestHash),
		}, nil
	}
	return nil, mapErr(meta.ErrNotFound)
}

// OpenChunk returns a chunk object proving user ownership. The app
// parameter enforces the token app allowlist even though chunk keys are
// per user.
func (s *Service) OpenChunk(ctx context.Context, p auth.Principal, app string, h api.Hash) (blob.Object, error) {
	if err := requireScope(p, auth.ScopeRead, app); err != nil {
		return nil, err
	}
	o, err := s.Blob.Open(ctx, blob.ChunkKey(p.User.ID, h))
	if errors.Is(err, blob.ErrNotFound) {
		return nil, mapErr(meta.ErrNotFound)
	}
	return o, err
}
