// SPDX-License-Identifier: 0BSD

package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/settings"
)

// adminOnly gates /v1/admin handlers.
func (s *Server) adminOnly(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	p, ok := s.authn(w, r)
	if !ok {
		return p, false
	}
	if !p.Admin {
		s.writeProblem(w, r, auth.ErrForbidden)
		return p, false
	}
	return p, true
}

func (s *Server) hAdminSettingsGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminOnly(w, r); !ok {
		return
	}
	out := map[string]any{"schema": settings.Schema()}
	if s.settings != nil {
		if m, ok := s.settings.(*settings.Manager); ok {
			out["values"] = m.Effective()
			out["overrides"] = m.Overrides()
		} else {
			out["values"] = s.settings.Effective()
		}
	}
	s.writeJSON(w, 200, out)
}

func (s *Server) hAdminSettingsPatch(w http.ResponseWriter, r *http.Request) {
	p, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	m, isMgr := s.settings.(*settings.Manager)
	if !isMgr {
		s.writeProblem(w, r, auth.ErrForbidden)
		return
	}
	var patch map[string]json.RawMessage
	if err := s.decodeJSON(w, r, &patch, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	ch, err := m.Update(r.Context(), p.User.ID, patch)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"changed": len(ch)})
}

func (s *Server) hAdminBan(w http.ResponseWriter, r *http.Request) {
	p, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	var in struct {
		Reason string `json:"reason"`
		Until  string `json:"until"`
		Revoke bool   `json:"revoke_tokens"`
	}
	if err := s.decodeJSON(w, r, &in, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	var until *time.Time
	if in.Until != "" {
		if t, err := time.Parse(time.RFC3339, in.Until); err == nil {
			until = &t
		}
	}
	err := s.Ban(r.Context(), p.User.ID, r.PathValue("id"), in.Reason, until, in.Revoke)
	s.respond(w, r, map[string]any{"ok": err == nil}, err)
}

func (s *Server) hAdminUnban(w http.ResponseWriter, r *http.Request) {
	p, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	err := s.Unban(r.Context(), p.User.ID, r.PathValue("id"))
	s.respond(w, r, map[string]any{"ok": err == nil}, err)
}

func (s *Server) hAdminApprove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	err := s.Approve(r.Context(), p.User.ID, r.PathValue("id"))
	s.respond(w, r, map[string]any{"ok": err == nil}, err)
}

func (s *Server) hAdminReject(w http.ResponseWriter, r *http.Request) {
	p, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	err := s.Reject(r.Context(), p.User.ID, r.PathValue("id"))
	s.respond(w, r, map[string]any{"ok": err == nil}, err)
}

func (s *Server) hAdminSetPassword(w http.ResponseWriter, r *http.Request) {
	p, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	var in struct {
		Password string `json:"password"`
		Generate bool   `json:"generate"`
	}
	if err := s.decodeJSON(w, r, &in, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	pw, err := s.AdminSetPassword(r.Context(), p.User.ID, r.PathValue("id"), in.Password, in.Generate)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"password": pw})
}

func (s *Server) hAdminInvites(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminOnly(w, r); !ok {
		return
	}
	inv, err := s.Meta.ListInvites(r.Context())
	s.respond(w, r, inv, err)
}

func (s *Server) hAdminInviteCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	var in struct {
		Label   string `json:"label"`
		MaxUses int    `json:"max_uses"`
		Expires string `json:"expires_at"`
	}
	if err := s.decodeJSON(w, r, &in, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	raw := make([]byte, 16)
	rand.Read(raw)
	code := "inv_" + hex.EncodeToString(raw)
	h := sha256.Sum256([]byte(code))
	id, _ := meta.NewID(s.now())
	var exp *time.Time
	if in.Expires != "" {
		if t, err := time.Parse(time.RFC3339, in.Expires); err == nil {
			exp = &t
		}
	}
	iv := meta.Invite{ID: id, CodeHash: h, CodePrefix: code[:min(6, len(code))],
		Label: in.Label, MaxUses: in.MaxUses, CreatedBy: p.User.ID,
		CreatedAt: ptrT(s.now()), ExpiresAt: exp}
	if err := s.Meta.CreateInvite(r.Context(), iv); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.audit(r.Context(), p.User.ID, "invite_create", "invite", id, "")
	s.writeJSON(w, 201, map[string]any{"code": code, "id": id})
}

func (s *Server) hAdminInviteDelete(w http.ResponseWriter, r *http.Request) {
	_, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	err := s.Meta.RevokeInvite(r.Context(), r.PathValue("id"))
	s.respond(w, r, map[string]any{"ok": err == nil}, err)
}

func (s *Server) hAdminBlocks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminOnly(w, r); !ok {
		return
	}
	b, err := s.Meta.ListIPBlocks(r.Context())
	s.respond(w, r, b, err)
}

func (s *Server) hAdminBlockCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	var in struct {
		CIDR    string `json:"cidr"`
		Reason  string `json:"reason"`
		Expires string `json:"expires_at"`
	}
	if err := s.decodeJSON(w, r, &in, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	var exp *time.Time
	if in.Expires != "" {
		if t, err := time.Parse(time.RFC3339, in.Expires); err == nil {
			exp = &t
		}
	}
	ctx := ctxWithIP(r.Context(), netx.ClientIPReal(r, s.trustedCIDRs(), s.Cfg.Proxy.RealIPHeader))
	err := s.AddIPBlock(ctx, p.User.ID, in.CIDR, in.Reason, exp)
	s.respond(w, r, map[string]any{"ok": err == nil}, err)
}

func (s *Server) hAdminBlockDelete(w http.ResponseWriter, r *http.Request) {
	_, ok := s.adminOnly(w, r)
	if !ok {
		return
	}
	err := s.RemoveIPBlock(r.Context(), r.PathValue("id"))
	s.respond(w, r, map[string]any{"ok": err == nil}, err)
}

func (s *Server) hAdminAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminOnly(w, r); !ok {
		return
	}
	q := r.URL.Query()
	f := meta.AuditFilter{Action: q.Get("action"), ActorID: q.Get("actor"),
		TargetID: q.Get("target"), Query: q.Get("q")}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = t
		}
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	ev, next, err := s.Meta.ListAudit(r.Context(), f, q.Get("cursor"), limit)
	s.respond(w, r, map[string]any{"events": ev, "cursor": next}, err)
}

func ptrT(t time.Time) *time.Time { return &t }
