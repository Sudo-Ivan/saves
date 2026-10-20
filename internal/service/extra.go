// SPDX-License-Identifier: 0BSD

package service

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
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
		return api.DecodeManifest(bytes.NewReader(b), int64(len(b))+1)
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
		if fa.Size != fb.Size || fa.ModTimeNS != fb.ModTimeNS || !sameChunks(fa, fb) {
			out = append(out, DiffEntry{Path: path, Kind: "changed"})
		}
	}
	for path := range am {
		if _, ok := bm[path]; !ok {
			out = append(out, DiffEntry{Path: path, Kind: "removed"})
		}
	}
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
func (s *Service) CreateToken(ctx context.Context, p auth.Principal, userID, name string, scopes []string, apps []string, expiresAt *time.Time) (TokenFlow, error) {
	var out TokenFlow
	if p.User.ID != userID && p.Scopes&auth.ScopeAdmin == 0 {
		return out, &api.Problem{Code: api.CodeForbidden, Title: "forbidden", Status: 403}
	}
	id, _, full, hash, err := auth.GenerateToken()
	if err != nil {
		return out, err
	}
	t := meta.Token{
		ID: id, UserID: userID, SecretHash: hash, Name: name,
		Scopes: scopes, Apps: apps, CreatedAt: s.now(), ExpiresAt: expiresAt,
	}
	if err := s.Meta.CreateToken(ctx, t); err != nil {
		return out, mapErr(err)
	}
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
	return mapErr(err)
}
