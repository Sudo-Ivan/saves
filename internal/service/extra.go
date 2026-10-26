// SPDX-License-Identifier: 0BSD

package service

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/chunkindex"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// WriteArchive streams a tar of the snapshot to w. Names are safe
// relative paths and dirs are included.
func (s *Service) WriteArchive(ctx context.Context, p auth.Principal, app, slot, id string, w io.Writer) error {
	b, _, err := s.GetManifest(ctx, p, app, slot, id)
	if err != nil {
		return err
	}
	m, err := api.DecodeManifest(bytes.NewReader(b), int64(len(b))+1)
	if err != nil {
		return err
	}
	if m.Enc != nil {
		return &api.Problem{Code: api.CodeEncrypted,
			Title: "snapshot is encrypted; use client pull", Status: 409}
	}
	tw := tar.NewWriter(w)
	defer tw.Close()
	for _, d := range m.Dirs {
		name := strings.TrimSuffix(d, "/") + "/"
		if strings.Contains(name, "..") {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			return err
		}
	}
	open := func(h api.Hash) (blob.Object, error) {
		return s.Blob.Open(ctx, blob.ChunkKey(p.User.ID, h))
	}
	for _, f := range m.Files {
		if strings.Contains(f.Path, "..") || strings.HasPrefix(f.Path, "/") {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: f.Path, Size: f.Size, Mode: int64(f.Mode & 0o777),
			ModTime: time.Unix(0, f.ModTimeNS), Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		if f.Inline != nil {
			if _, err := tw.Write(f.Inline); err != nil {
				return err
			}
			continue
		}
		r, err := chunkindex.New(f.Chunks, f.Size, open)
		if err != nil {
			return err
		}
		_, err = io.CopyN(tw, r, f.Size)
		_ = r.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// DiffEntry describes one path difference between snapshots.
type DiffEntry struct {
	Path string
	Kind string // added, removed, changed
}

// Diff lists added, removed and changed paths between two snapshots.
func (s *Service) Diff(ctx context.Context, p auth.Principal, app, slot, idA, idB string) ([]DiffEntry, error) {
	load := func(id string) (*api.Manifest, error) {
		b, _, err := s.GetManifest(ctx, p, app, slot, id)
		if err != nil {
			return nil, err
		}
		m, err := api.DecodeManifest(bytes.NewReader(b), int64(len(b))+1)
		if err != nil {
			return nil, err
		}
		if m.Enc != nil {
			return nil, &api.Problem{Code: api.CodeEncrypted,
				Title: "snapshot is encrypted; use client pull", Status: 409}
		}
		return m, nil
	}
	ma, err := load(idA)
	if err != nil {
		return nil, err
	}
	mb, err := load(idB)
	if err != nil {
		return nil, err
	}
	am := map[string]api.File{}
	for _, f := range ma.Files {
		am[f.Path] = f
	}
	bm := map[string]api.File{}
	for _, f := range mb.Files {
		bm[f.Path] = f
	}
	var out []DiffEntry
	for path, fb := range bm {
		fa, ok := am[path]
		if !ok {
			out = append(out, DiffEntry{Path: path, Kind: "added"})
			continue
		}
		if fa.Size != fb.Size || fa.ModTimeNS != fb.ModTimeNS || !sameChunks(fa, fb) || !bytes.Equal(fa.Inline, fb.Inline) {
			out = append(out, DiffEntry{Path: path, Kind: "changed"})
		}
	}
	for path := range am {
		if _, ok := bm[path]; !ok {
			out = append(out, DiffEntry{Path: path, Kind: "removed"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func sameChunks(a, b api.File) bool {
	if len(a.Chunks) != len(b.Chunks) {
		return false
	}
	for i := range a.Chunks {
		if a.Chunks[i].Hash != b.Chunks[i].Hash {
			return false
		}
	}
	return true
}

// Admin ops.

func requireAdmin(p auth.Principal) error {
	if p.Scopes&auth.ScopeAdmin == 0 {
		return &api.Problem{Code: api.CodeForbidden, Title: "admin required", Status: 403}
	}
	return nil
}

// AdminListUsers pages users.
func (s *Service) AdminListUsers(ctx context.Context, p auth.Principal, after string, limit int) ([]meta.User, error) {
	if err := requireAdmin(p); err != nil {
		return nil, err
	}
	out, err := s.Meta.ListUsers(ctx, after, limit)
	return out, mapErr(err)
}

// AdminGetUser returns one user plus usage.
func (s *Service) AdminGetUser(ctx context.Context, p auth.Principal, id string) (meta.User, meta.Usage, error) {
	if err := requireAdmin(p); err != nil {
		return meta.User{}, meta.Usage{}, err
	}
	u, err := s.Meta.GetUser(ctx, id)
	if err != nil {
		return meta.User{}, meta.Usage{}, mapErr(err)
	}
	us, err := s.Meta.Usage(ctx, id)
	return u, us, mapErr(err)
}

// AdminPatchUser applies a patch.
func (s *Service) AdminPatchUser(ctx context.Context, p auth.Principal, id string, patch meta.UserPatch) (meta.User, error) {
	if err := requireAdmin(p); err != nil {
		return meta.User{}, err
	}
	u, err := s.Meta.UpdateUser(ctx, id, patch)
	return u, mapErr(err)
}

// AdminDeleteUser soft deletes a user.
func (s *Service) AdminDeleteUser(ctx context.Context, p auth.Principal, id string) error {
	if err := requireAdmin(p); err != nil {
		return err
	}
	return mapErr(s.Meta.DeleteUser(ctx, id))
}

// TokenFlow is the admin create-token result.
type TokenFlow struct {
	Token meta.Token
	Full  string
}

// CreateToken mints a token for a user (admin or self).
func (s *Service) CreateToken(ctx context.Context, p auth.Principal, userID, name string, scopes []string, apps []string, expiresAt *time.Time, cidrs []string) (TokenFlow, error) {
	var out TokenFlow
	if p.User.ID != userID && p.Scopes&auth.ScopeAdmin == 0 {
		return out, &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	name = strings.TrimSpace(name)
	if len(name) > 128 {
		return out, &api.Problem{Code: api.CodeBadRequest, Title: "token name too long", Status: 400}
	}
	// A token can never out-scope or out-range its creator.
	req, err := auth.ParseScopes(strings.Join(scopes, ","))
	if err != nil {
		return out, &api.Problem{Code: api.CodeBadRequest, Title: "unknown scope", Status: 400}
	}
	if req == 0 {
		return out, &api.Problem{Code: api.CodeBadRequest, Title: "at least one scope is required", Status: 400}
	}
	if expiresAt, err = s.ResolveExpiry(expiresAt, true); err != nil {
		return out, err
	}
	if cidrs, err = NormalizeCIDRs(cidrs); err != nil {
		return out, err
	}
	if req&^p.Scopes != 0 {
		return out, &api.Problem{Code: api.CodeForbidden, Title: "scopes exceed the caller's own", Status: 403}
	}
	if len(p.Apps) > 0 {
		if len(apps) == 0 {
			apps = p.Apps
		} else {
			for _, a := range apps {
				ok := false
				for _, allowed := range p.Apps {
					if a == allowed {
						ok = true
						break
					}
				}
				if !ok {
					return out, &api.Problem{Code: api.CodeForbidden, Title: "app outside the caller's allowlist", Status: 403}
				}
			}
		}
	}
	maxPer := s.TokenMaxPerUser
	if s.TokenPolicy != nil {
		_, _, maxPer = s.TokenPolicy()
	}
	if maxPer > 0 {
		toks, err := s.Meta.ListTokens(ctx, userID)
		if err != nil {
			return out, mapErr(err)
		}
		active := 0
		for _, t := range toks {
			if t.RevokedAt == nil && (t.ExpiresAt == nil || t.ExpiresAt.After(s.now())) {
				active++
			}
		}
		if active >= maxPer {
			return out, &api.Problem{Code: api.CodeConflict, Title: "token limit reached", Status: 409}
		}
	}
	id, _, full, hash, err := auth.GenerateToken()
	if err != nil {
		return out, err
	}
	t := meta.Token{
		ID: id, UserID: userID, SecretHash: hash, Name: name,
		Scopes: scopes, Apps: apps, CreatedAt: s.now(), ExpiresAt: expiresAt,
		AllowedCIDRs: cidrs,
	}
	if err := s.Meta.CreateToken(ctx, t); err != nil {
		return out, mapErr(err)
	}
	s.emitAudit(ctx, t.ID, userID, "created", "", p.User.ID, "", "web|api|cli")
	t.SecretHash = [32]byte{}
	out = TokenFlow{Token: t, Full: full}
	return out, nil
}

// ListTokens lists a user's tokens.
func (s *Service) ListTokens(ctx context.Context, p auth.Principal, userID string) ([]meta.Token, error) {
	if p.User.ID != userID && p.Scopes&auth.ScopeAdmin == 0 {
		return nil, &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	out, err := s.Meta.ListTokens(ctx, userID)
	for i := range out {
		out[i].SecretHash = [32]byte{}
	}
	return out, mapErr(err)
}

// RevokeToken revokes one token.
func (s *Service) RevokeToken(ctx context.Context, p auth.Principal, tokenID string) error {
	t, err := s.Meta.GetToken(ctx, tokenID)
	if err != nil {
		return mapErr(err)
	}
	if t.UserID != p.User.ID && p.Scopes&auth.ScopeAdmin == 0 {
		return &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	err = s.Meta.RevokeToken(ctx, tokenID)
	if err == nil && s.TokenInvalidator != nil {
		s.TokenInvalidator(tokenID)
	}
	if err == nil {
		s.emitAudit(ctx, tokenID, t.UserID, "revoked", "", p.User.ID, "", "")
	}
	return mapErr(err)
}

// UpdateToken edits name, expiry and CIDRs of a token.
func (s *Service) UpdateToken(ctx context.Context, p auth.Principal, tokenID string, patch meta.TokenPatch) error {
	t, err := s.Meta.GetToken(ctx, tokenID)
	if err != nil {
		return mapErr(err)
	}
	if t.UserID != p.User.ID && p.Scopes&auth.ScopeAdmin == 0 {
		return &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	if t.RevokedAt != nil {
		return &api.Problem{Code: api.CodeConflict, Title: "token is revoked", Status: 409}
	}
	var changed []string
	if patch.Name != nil {
		n := strings.TrimSpace(*patch.Name)
		if len(n) > 128 {
			return &api.Problem{Code: api.CodeBadRequest, Title: "token name too long", Status: 400}
		}
		patch.Name = &n
		changed = append(changed, "name")
	}
	if patch.ExpiresAt != nil {
		exp, err := s.ResolveExpiry(*patch.ExpiresAt, false)
		if err != nil {
			return err
		}
		patch.ExpiresAt = &exp
		changed = append(changed, "expiry")
	}
	if patch.CIDRs != nil {
		c, err := NormalizeCIDRs(*patch.CIDRs)
		if err != nil {
			return err
		}
		patch.CIDRs = &c
		changed = append(changed, "cidrs")
	}
	if len(changed) == 0 {
		return nil
	}
	if err := s.Meta.UpdateToken(ctx, tokenID, patch); err != nil {
		return mapErr(err)
	}
	if s.TokenInvalidator != nil {
		s.TokenInvalidator(tokenID)
	}
	kinds := map[string]string{"name": "renamed", "expiry": "expiry_changed", "cidrs": "cidr_changed"}
	for _, c := range changed {
		s.emitAudit(ctx, tokenID, t.UserID, kinds[c], "", p.User.ID, "", c)
	}
	return nil
}

// MaxTokenLifetime bounds any expiry, even with max_ttl unset.
const MaxTokenLifetime = 10 * 365 * 24 * time.Hour

// ResolveExpiry validates a requested expiry. A nil request means no
// expiry, which max_ttl turns into now+max_ttl when creating and
// rejects when editing.
func (s *Service) ResolveExpiry(exp *time.Time, creating bool) (*time.Time, error) {
	maxTTL := s.TokenMaxTTL
	if s.TokenPolicy != nil {
		maxTTL, _, _ = s.TokenPolicy()
	}
	return ResolveTokenExpiry(s.now(), maxTTL, exp, creating)
}

// ResolveTokenExpiry is ResolveExpiry with explicit inputs for callers
// that hold no Service, such as the admin CLI.
func ResolveTokenExpiry(now time.Time, maxTTL time.Duration, exp *time.Time, creating bool) (*time.Time, error) {
	if exp == nil {
		if maxTTL > 0 {
			if !creating {
				return nil, &api.Problem{Code: api.CodeBadRequest, Title: "an expiry is required by max_ttl", Status: 400}
			}
			t := now.Add(maxTTL)
			return &t, nil
		}
		return nil, nil
	}
	t := exp.UTC()
	if !t.After(now) {
		return nil, &api.Problem{Code: api.CodeBadRequest, Title: "expiry must be in the future", Status: 400}
	}
	if t.After(now.Add(MaxTokenLifetime)) {
		return nil, &api.Problem{Code: api.CodeBadRequest, Title: "expiry is too far in the future", Status: 400}
	}
	if maxTTL > 0 && t.After(now.Add(maxTTL)) {
		return nil, &api.Problem{Code: api.CodeBadRequest, Title: "expiry beyond max_ttl", Status: 400}
	}
	return &t, nil
}

// ParseTTL parses a lifetime such as 720h, 30d or 90m.
func ParseTTL(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if strings.HasSuffix(v, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if err != nil || n <= 0 || n > 3660 {
			return 0, &api.Problem{Code: api.CodeBadRequest, Title: "invalid expires_in", Status: 400}
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Minute || d > MaxTokenLifetime {
		return 0, &api.Problem{Code: api.CodeBadRequest, Title: "invalid expires_in", Status: 400}
	}
	return d, nil
}

// NormalizeCIDRs validates and canonicalizes an allowlist.
func NormalizeCIDRs(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out, err := auth.ValidateCIDRs(strings.Join(in, "\n"))
	if err != nil {
		return nil, &api.Problem{Code: api.CodeBadRequest, Title: "invalid allowed_cidrs", Detail: err.Error(), Status: 400}
	}
	return out, nil
}

// TokenEvents lists audit rows for one token (owner or admin).
func (s *Service) TokenEvents(ctx context.Context, p auth.Principal, tokenID, kind, cursor string, limit int) ([]meta.TokenEvent, string, error) {
	t, err := s.Meta.GetToken(ctx, tokenID)
	if err != nil {
		return nil, "", mapErr(err)
	}
	if t.UserID != p.User.ID && p.Scopes&auth.ScopeAdmin == 0 {
		return nil, "", &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	return s.Meta.ListTokenEvents(ctx, tokenID, kind, cursor, limit)
}

// TokenStats returns aggregated stats (owner or admin).
func (s *Service) TokenStats(ctx context.Context, p auth.Principal, tokenID string) (meta.TokenStats, error) {
	var st meta.TokenStats
	t, err := s.Meta.GetToken(ctx, tokenID)
	if err != nil {
		return st, mapErr(err)
	}
	if t.UserID != p.User.ID && p.Scopes&auth.ScopeAdmin == 0 {
		return st, &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	return s.Meta.TokenStats(ctx, tokenID)
}

// GetToken returns one token to owner or admin.
func (s *Service) GetToken(ctx context.Context, p auth.Principal, tokenID string) (meta.Token, error) {
	var t meta.Token
	t, err := s.Meta.GetToken(ctx, tokenID)
	if err != nil {
		return t, mapErr(err)
	}
	if t.UserID != p.User.ID && p.Scopes&auth.ScopeAdmin == 0 {
		return t, &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	t.SecretHash = [32]byte{}
	return t, nil
}

type clientKey struct{}

type clientInfo struct{ IP, UA string }

// WithClient attaches the caller's address and user agent so audit
// events written during the request can record them.
func WithClient(ctx context.Context, ip, ua string) context.Context {
	return context.WithValue(ctx, clientKey{}, clientInfo{ip, ua})
}

// emitAudit writes a management audit event when auditing is on.
func (s *Service) emitAudit(ctx context.Context, tokenID, userID, kind, ip, actor, ua, detail string) {
	if !s.AuditEnabled {
		return
	}
	if ci, ok := ctx.Value(clientKey{}).(clientInfo); ok {
		if ip == "" {
			ip = ci.IP
		}
		if ua == "" {
			ua = ci.UA
		}
	}
	if len(ua) > 200 {
		ua = ua[:200]
	}
	ua = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, ua)
	id, err := meta.NewID(s.now())
	if err != nil {
		return
	}
	_ = s.Meta.InsertTokenEvent(ctx, meta.TokenEvent{
		ID: id, TokenID: tokenID, UserID: userID, At: s.now(), Kind: kind,
		IP: ip, ActorID: actor, UserAgent: ua, Detail: detail,
	})
}
