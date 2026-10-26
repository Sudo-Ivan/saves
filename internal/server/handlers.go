// SPDX-License-Identifier: 0BSD

package server

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func (s *Server) hMe(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	u, usage, err := s.Svc.Me(r.Context(), p)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{
		"user": u, "tier": u.Tier,
		"usage": map[string]any{
			"used_bytes": usage.UsedBytes, "reserved_bytes": usage.ReservedBytes,
			"quota_bytes": usage.QuotaBytes, "slots": usage.Slots, "snapshots": usage.Snapshots,
		},
		"scopes": p.Scopes.String(), "anonymous": p.Anonymous,
		"require_encryption": s.Svc.RequireEncryption(r.Context(), p),
		"limits":             s.Cfg.Limits.APILimits(),
		"tier_limits":        s.tierLimits(r, p, u),
		"bandwidth":          s.bwMe(r, p, u),
	})
}

func (s *Server) hRegister(w http.ResponseWriter, r *http.Request) {
	if s.Reg == nil {
		s.writeProblem(w, r, auth.ErrForbidden)
		return
	}
	var in struct {
		Invite string `json:"invite"`
	}
	if err := s.decodeJSON(w, r, &in, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	res, err := s.Reg.Register(r.Context(), s.clientIP(r), in.Invite)
	if err != nil {
		if errors.Is(err, auth.ErrPendingApproval) {
			s.writeJSON(w, 202, map[string]any{"code": "pending_approval", "user_id": res.User.ID})
			return
		}
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 201, map[string]any{
		"user_id": res.User.ID, "token": res.Token, "created_at": res.CreatedAt,
	})
}

func (s *Server) hApps(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	out, err := s.Svc.ListApps(r.Context(), p)
	s.respond(w, r, out, err)
}

func (s *Server) hSlots(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	out, err := s.Svc.ListSlots(r.Context(), p, r.PathValue("app"))
	s.respond(w, r, out, err)
}

func (s *Server) hSlot(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	out, err := s.Svc.GetSlot(r.Context(), p, r.PathValue("app"), r.PathValue("slot"))
	s.respond(w, r, out, err)
}

func (s *Server) hSlotDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	err := s.Svc.DeleteSlot(r.Context(), p, r.PathValue("app"), r.PathValue("slot"))
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) hBegin(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	var m api.Manifest
	if err := s.decodeJSON(w, r, &m, s.Cfg.Limits.MaxManifestBytes.Int64()); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	out, err := s.Svc.BeginSnapshot(r.Context(), p, r.PathValue("app"), r.PathValue("slot"),
		m.Device, m.Label, m.Parent, m)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	missing := make([]string, len(out.Missing))
	for i, h := range out.Missing {
		missing[i] = hex.EncodeToString(h[:])
	}
	s.writeJSON(w, 201, map[string]any{
		"id": out.ID, "missing": missing, "expires_at": out.ExpiresAt,
		"chunk_url": "/v1/apps/" + r.PathValue("app") + "/slots/" + r.PathValue("slot") +
			"/snapshots/" + out.ID + "/chunks/",
	})
}

func (s *Server) hListSnapshots(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	out, next, err := s.Svc.ListSnapshots(r.Context(), p, r.PathValue("app"), r.PathValue("slot"),
		r.URL.Query().Get("cursor"), limit)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"snapshots": out, "next": next})
}

// manifestBody fetches and returns manifest bytes for a snapshot id.
func (s *Server) manifestBody(w http.ResponseWriter, r *http.Request, p auth.Principal, id string) ([]byte, api.Hash, bool) {
	b, h, err := s.Svc.GetManifest(r.Context(), p, r.PathValue("app"), r.PathValue("slot"), id)
	if err != nil {
		s.writeProblem(w, r, err)
		return nil, api.Hash{}, false
	}
	return b, h, true
}

var gzPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(nil, gzip.DefaultCompression); return w }}

func (s *Server) hGetSnapshot(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	b, h, ok := s.manifestBody(w, r, p, r.PathValue("id"))
	if !ok {
		return
	}
	etag := `"` + hex.EncodeToString(h[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, immutable")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(304)
		return
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		gz := gzPool.Get().(*gzip.Writer)
		gz.Reset(w)
		_, _ = gz.Write(b)
		_ = gz.Close()
		gzPool.Put(gz)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(b) // #nosec G705 -- content type is application/json
}

func (s *Server) hDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if err := s.Svc.DeleteSnapshot(r.Context(), p, r.PathValue("app"), r.PathValue("slot"), r.PathValue("id")); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) hCommit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	var expected string
	if im := r.Header.Get("If-Match"); im != "" {
		expected = strings.Trim(im, `"`)
	}
	force := r.URL.Query().Get("force") == "1"
	res, err := s.Svc.CommitSnapshot(r.Context(), p, r.PathValue("app"), r.PathValue("slot"),
		r.PathValue("id"), expected, force)
	if err != nil {
		var ce *meta.ConflictError
		if errors.As(err, &ce) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": api.CodeConflict, "title": "head conflict", "status": 409,
				"head": ce.Head,
			})
			return
		}
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, res.Snapshot)
}

func (s *Server) hPutChunk(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	h, err := api.ParseHash(r.PathValue("hash"))
	if err != nil {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeBadRequest, Title: "bad hash", Status: 400})
		return
	}
	if r.ContentLength < 0 {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeBadRequest, Title: "content length required", Status: 411})
		return
	}
	lim := s.Cfg.Limits.MaxChunkBytes.Int64()
	if lim > 0 && r.ContentLength > lim+api.ChunkSlack {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeTooLarge, Title: "chunk too large", Status: 413})
		return
	}
	err = s.Svc.PutChunk(r.Context(), p, r.PathValue("app"), r.PathValue("slot"),
		r.PathValue("id"), h, r.Body, r.ContentLength)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.WriteHeader(201)
}

func (s *Server) hGetFile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	path := r.PathValue("path")
	// The mux already URL-decodes; reject residual control chars.
	if strings.ContainsAny(path, "\x00") {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeBadRequest, Title: "bad path", Status: 400})
		return
	}
	if err := api.ValidatePath(path, 64); err != nil {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeBadRequest, Title: "bad path", Status: 400})
		return
	}
	fh, err := s.Svc.OpenFile(r.Context(), p, r.PathValue("app"), r.PathValue("slot"), r.PathValue("id"), path)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	defer func() {
		if c, ok2 := fh.Reader.(io.Closer); ok2 {
			_ = c.Close()
		}
	}()
	w.Header().Set("ETag", fh.ETag)
	w.Header().Set("Cache-Control", "private, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(path)+"\"")
	// Cap multi-range fan-out so bytes=0-,0-,... cannot amplify output.
	if rg := r.Header.Get("Range"); rg != "" && strings.Count(rg, ",") > 15 {
		w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(fh.Size, 10))
		s.writeProblem(w, r, &api.Problem{Code: api.CodeBadRequest, Title: "too many ranges", Status: 416})
		return
	}
	http.ServeContent(w, r, path, fh.ModTime, fh.Reader)
}

func sanitizeFilename(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i >= 0 {
		p = p[i+1:]
	}
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 {
			return '_'
		}
		return r
	}, p)
}

func (s *Server) hArchive(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="archive.tar"`)
	w.WriteHeader(200)
	if err := s.Svc.WriteArchive(r.Context(), p, r.PathValue("app"), r.PathValue("slot"), r.PathValue("id"), w); err != nil {
		s.Log.Error("archive", "err", err)
	}
}

func (s *Server) hDiff(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	out, err := s.Svc.Diff(r.Context(), p, r.PathValue("app"), r.PathValue("slot"), r.PathValue("a"), r.PathValue("b"))
	s.respond(w, r, out, err)
}

func (s *Server) hGetChunk(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	h, err := api.ParseHash(r.PathValue("hash"))
	if err != nil {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeBadRequest, Title: "bad hash", Status: 400})
		return
	}
	o, err := s.Svc.OpenChunk(r.Context(), p, r.PathValue("app"), h)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	defer o.Close()
	w.Header().Set("ETag", `"`+hex.EncodeToString(h[:])+`"`)
	w.Header().Set("Cache-Control", "private, immutable")
	// ServeContent will use ReaderFrom for file-backed objects.
	http.ServeContent(w, r, "", time.Time{}, io.NewSectionReader(o, 0, o.Size()))
}

// Admin.

func (s *Server) hAdminUsers(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	out, err := s.Svc.AdminListUsers(r.Context(), p, r.URL.Query().Get("after"), limit)
	s.respond(w, r, out, err)
}

func (s *Server) hAdminUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	u, us, err := s.Svc.AdminGetUser(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"user": u, "usage": us})
}

func (s *Server) hAdminPatchUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	var in struct {
		Tier       *string `json:"tier"`
		QuotaBytes *int64  `json:"quota_bytes"`
		ClearQuota bool    `json:"clear_quota"`
		Disabled   *bool   `json:"disabled"`
	}
	if err := s.decodeJSON(w, r, &in, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	patch := meta.UserPatch{Tier: in.Tier, Disabled: in.Disabled}
	if in.ClearQuota {
		patch.QuotaBytes = &meta.Optional[int64]{Set: true, Null: true}
	} else if in.QuotaBytes != nil {
		patch.QuotaBytes = &meta.Optional[int64]{Set: true, Value: *in.QuotaBytes}
	}
	u, err := s.Svc.AdminPatchUser(r.Context(), p, r.PathValue("id"), patch)
	s.respond(w, r, u, err)
}

func (s *Server) hAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if err := s.Svc.AdminDeleteUser(r.Context(), p, r.PathValue("id")); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) hAdminListTokens(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	out, err := s.Svc.ListTokens(r.Context(), p, r.PathValue("id"))
	s.respond(w, r, out, err)
}

func (s *Server) hAdminCreateToken(w http.ResponseWriter, r *http.Request) {
	s.createToken(w, r, r.PathValue("id"))
}

func (s *Server) hAdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	err := s.Svc.RevokeToken(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) hAdminStats(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if p.Scopes&auth.ScopeAdmin == 0 {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeForbidden, Title: "admin required", Status: 403})
		return
	}
	s.writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) hAdminGC(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if p.Scopes&auth.ScopeAdmin == 0 {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeForbidden, Title: "admin required", Status: 403})
		return
	}
	if s.gc != nil {
		go func() { _, _ = s.gc.RunOnce(context.Background()) }() // #nosec G118 -- detached gc outlives the request
	}
	w.WriteHeader(202)
}

// Self token management.

func (s *Server) hMyTokens(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	out, err := s.Svc.ListTokens(r.Context(), p, p.User.ID)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, viewTokens(out))
}

func (s *Server) hMyTokenCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	s.createToken(w, r, p.User.ID)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, userID string) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	var in struct {
		Name         string   `json:"name"`
		Scopes       []string `json:"scopes"`
		Apps         []string `json:"apps"`
		ExpiresAt    *string  `json:"expires_at"`
		ExpiresIn    string   `json:"expires_in"`
		AllowedCIDRs []string `json:"allowed_cidrs"`
	}
	if err := s.decodeJSON(w, r, &in, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	var raw json.RawMessage
	if in.ExpiresAt != nil {
		raw, _ = json.Marshal(*in.ExpiresAt)
	}
	exp, _, err := expiryInput(raw, in.ExpiresIn)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	out, err := s.Svc.CreateToken(r.Context(), p, userID, in.Name, in.Scopes, in.Apps, exp, in.AllowedCIDRs)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 201, map[string]any{"id": out.Token.ID, "token": out.Full, "expires_at": out.Token.ExpiresAt, "allowed_cidrs": viewToken(out.Token).AllowedCIDRs})
}

func (s *Server) hMyTokenRevoke(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if err := s.Svc.RevokeToken(r.Context(), p, r.PathValue("id")); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.WriteHeader(204)
}

// helpers

func (s *Server) respond(w http.ResponseWriter, r *http.Request, v any, err error) {
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, v)
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &api.Problem{Code: api.CodeBadRequest, Title: "invalid json", Status: 400, Detail: err.Error()}
	}
	if dec.More() {
		return &api.Problem{Code: api.CodeBadRequest, Title: "trailing data", Status: 400}
	}
	return nil
}

// hVaultGet returns the stored vault header with its version ETag.
func (s *Server) hVaultGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if p.Scopes&auth.ScopeRead == 0 {
		s.writeProblem(w, r, auth.ErrForbidden)
		return
	}
	rec, err := s.Svc.GetVault(r.Context(), p)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, rec.Version))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(200)
	_, _ = w.Write(rec.Header)
}

// hVaultPut stores the vault header, requiring If-Match when one exists.
func (s *Server) hVaultPut(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if p.Scopes&auth.ScopeWrite == 0 {
		s.writeProblem(w, r, auth.ErrForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8192+1))
	if err != nil || len(body) > 8192 {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeTooLarge,
			Title: "vault header too large", Status: 413})
		return
	}
	var ifv *int64
	existing, gerr := s.Svc.GetVault(r.Context(), p)
	if gerr == nil {
		m := r.Header.Get("If-Match")
		var v int64
		_, _ = fmt.Sscanf(m, `"%d"`, &v)
		if m != `"-1"` && v != existing.Version {
			s.writeProblem(w, r, &api.Problem{Code: api.CodeConflict,
				Title: "version mismatch", Status: 412})
			return
		}
		ifv = &v
	} else {
		if v := r.Header.Get("If-Match"); v != "" && v != `"0"` {
			s.writeProblem(w, r, &api.Problem{Code: api.CodeConflict,
				Title: "version mismatch", Status: 412})
			return
		}
	}
	// Extract kid if the blob is JSON.
	kid := ""
	var j map[string]any
	if json.Unmarshal(body, &j) == nil {
		if k, ok := j["kid"].(string); ok {
			kid = k
		}
	}
	ver, err := s.Svc.PutVault(r.Context(), p, body, kid, ifv)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, ver))
	s.writeJSON(w, 200, map[string]any{"version": ver})
}

// hVaultDelete removes the vault header.
func (s *Server) hVaultDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if p.Scopes&auth.ScopeWrite == 0 {
		s.writeProblem(w, r, auth.ErrForbidden)
		return
	}
	if err := s.Svc.DeleteVault(r.Context(), p); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	w.WriteHeader(204)
}

// hEvents streams server-sent events for the authenticated user.
func (s *Server) hEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	if p.Scopes&auth.ScopeRead == 0 {
		s.writeProblem(w, r, auth.ErrForbidden)
		return
	}
	ch, drop, err := s.Svc.Events.Subscribe(p.User.ID)
	if err != nil {
		s.writeProblem(w, r, &api.Problem{Code: "too_many_streams",
			Title: "too many event streams", Status: 429})
		return
	}
	defer drop()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	fl, _ := w.(http.Flusher)
	fmt.Fprintf(w, ": keepalive\nretry: 5000\n\n")
	if fl != nil {
		fl.Flush()
	}
	ctx := r.Context()
	idle := time.NewTicker(15 * time.Second)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok2 := <-ch:
			if !ok2 {
				return
			}
			var b strings.Builder
			b.WriteString("id: ")
			b.WriteString(strconv.FormatInt(ev.ID, 10))
			b.WriteString("\nevent: " + ev.Type + "\n")
			for _, ln := range strings.Split(string(ev.Data), "\n") {
				b.WriteString("data: " + ln + "\n")
			}
			b.WriteString("\n")
			if _, err := io.WriteString(w, b.String()); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		case <-idle.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	}
}

// tierLimits resolves the caller's tier for /v1/me.
func (s *Server) tierLimits(r *http.Request, p auth.Principal, u meta.User) map[string]any {
	e, err := s.Svc.Quota.For(u, "", p.Anonymous)
	if err != nil {
		return nil
	}
	return map[string]any{
		"quota_bytes":            e.QuotaBytes,
		"max_slots":              e.MaxSlots,
		"max_pending_snapshots":  e.MaxPendingSnapshots,
		"max_snapshots_per_slot": e.KeepLast,
		"max_files":              e.APILimits.MaxFiles,
		"max_file_bytes":         e.APILimits.MaxFileBytes,
		"max_snapshot_bytes":     e.APILimits.MaxSnapshotBytes,
	}
}

// bwMe returns the /v1/me bandwidth object.
func (s *Server) bwMe(r *http.Request, p auth.Principal, u meta.User) map[string]any {
	if s.bw == nil {
		return map[string]any{"enabled": false}
	}
	e, _ := s.Svc.Quota.For(u, "", p.Anonymous)
	var pol policy
	bp := e.Bandwidth
	pol = policy{upBps: bp.UpBps.Int64(), downBps: bp.DownBps.Int64(),
		daily: bp.Daily.Int64(), monthly: bp.Monthly.Int64()}
	return s.bw.Snapshot(r.Context(), u.ID, pol)
}
