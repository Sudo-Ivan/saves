// SPDX-License-Identifier: 0BSD

package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

func (s *Server) whAdmin(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	// Same source as the API: page the full user list for the count.
	count := 0
	after := ""
	for {
		users, err := s.Svc.AdminListUsers(r.Context(), wv.principal(), after, 200)
		if err != nil {
			s.webServiceError(wv, err)
			return
		}
		count += len(users)
		if len(users) < 200 {
			break
		}
		after = users[len(users)-1].ID
	}
	notice := ""
	if r.URL.Query().Get("gc") == "1" {
		notice = "Garbage collection complete."
	}
	wv.render("admin", 200, struct {
		Users   int
		Version string
		Notice  string
	}{Users: count, Version: s.Version, Notice: notice})
}

func (s *Server) whAdminUsers(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	users, err := s.Svc.AdminListUsers(r.Context(), wv.principal(), r.URL.Query().Get("after"), 50)
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	more, after := false, ""
	if len(users) == 50 {
		more = true
		after = users[len(users)-1].ID
	}
	wv.render("admin_users", 200, struct {
		Users []meta.User
		More  bool
		After string
	}{Users: users, More: more, After: after})
}

func (s *Server) whAdminUser(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	s.renderAdminUser(wv, "", "")
}

func (s *Server) renderAdminUser(wv *webReq, notice, errMsg string) {
	r := wv.r
	u, usage, err := s.Svc.AdminGetUser(r.Context(), wv.principal(), r.PathValue("id"))
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	var cred *meta.WebCredential
	if c, err := s.Meta.GetCredential(r.Context(), u.ID); err == nil {
		cc := c
		cred = &cc
	}
	wv.render("admin_user", 200, struct {
		U      meta.User
		Usage  meta.Usage
		Cred   *meta.WebCredential
		Notice string
		Error  string
		Tokens []tokenRow
	}{U: u, Usage: usage, Cred: cred, Notice: notice, Error: errMsg, Tokens: s.adminUserTokens(wv, u.ID)})
}

func (s *Server) whAdminUserDeleteGet(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	id := r.PathValue("id")
	wv.render("confirm", 200, struct {
		Heading string
		Warning string
		URL     string
		Back    string
	}{
		Heading: "Delete user",
		Warning: "User " + id + " will be disabled and deleted.",
		URL:     wv.web.link + "admin/users/" + id,
		Back:    wv.web.link + "admin/users/" + id,
	})
}

func (s *Server) whAdminUserPost(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	id := r.PathValue("id")
	action := r.PostForm.Get("action")
	switch action {
	case "disable", "delete", "revoke_admin", "reset_2fa":
		s.audit(wv.r.Context(), wv.sess.UserID, action, "user", id, "")
		if id == wv.sess.UserID {
			s.renderAdminUser(wv, "", "You cannot apply that action to your own account.")
			return
		}
	}
	p := wv.principal()
	audit := func() { s.Log.Info("web admin action", "actor", wv.sess.UserID, "target", id, "action", action) }
	fail := func(err error) {
		if errors.Is(err, meta.ErrNotFound) {
			wv.errorPage(404)
			return
		}
		s.webServiceError(wv, err)
	}
	switch action {
	case "set_tier":
		tier := r.PostForm.Get("tier")
		if _, err := s.Svc.AdminPatchUser(r.Context(), p, id, meta.UserPatch{Tier: &tier}); err != nil {
			fail(err)
			return
		}
	case "set_quota":
		q := r.PostForm.Get("quota")
		var patch meta.UserPatch
		if q == "" || q == "0" {
			patch.QuotaBytes = &meta.Optional[int64]{Set: true, Null: true}
		} else {
			n, err := strconv.ParseInt(q, 10, 64)
			if err != nil || n < 0 {
				s.renderAdminUser(wv, "", "Quota must be a non-negative byte count.")
				return
			}
			patch.QuotaBytes = &meta.Optional[int64]{Set: true, Value: n}
		}
		if _, err := s.Svc.AdminPatchUser(r.Context(), p, id, patch); err != nil {
			fail(err)
			return
		}
	case "disable", "enable":
		dis := action == "disable"
		if _, err := s.Svc.AdminPatchUser(r.Context(), p, id, meta.UserPatch{Disabled: &dis}); err != nil {
			fail(err)
			return
		}
		if dis {
			_, _ = s.Meta.DeleteUserSessions(r.Context(), id, nil)
		}
	case "delete":
		if err := s.Svc.AdminDeleteUser(r.Context(), p, id); err != nil {
			fail(err)
			return
		}
		_, _ = s.Meta.DeleteUserSessions(r.Context(), id, nil)
		audit()
		http.Redirect(w, r, wv.web.link+"admin/users", http.StatusSeeOther)
		return
	case "revoke_sessions":
		s.audit(wv.r.Context(), wv.sess.UserID, "revoke_sessions", "user", id, "")
		if _, err := s.Meta.DeleteUserSessions(r.Context(), id, nil); err != nil {
			fail(err)
			return
		}
	case "grant_admin", "revoke_admin":
		s.audit(wv.r.Context(), wv.sess.UserID, action, "user", id, "")
		v := action == "grant_admin"
		if err := s.Meta.UpdateCredential(r.Context(), id, meta.CredentialPatch{Admin: &v}); err != nil {
			fail(err)
			return
		}
		// Role change kills existing sessions.
		_, _ = s.Meta.DeleteUserSessions(r.Context(), id, nil)
	case "reset_2fa":
		no := false
		empty := []byte{}
		zero := int64(0)
		if err := s.Meta.UpdateCredential(r.Context(), id, meta.CredentialPatch{
			TOTPSecret: &empty, TOTPEnabled: &no, TOTPLastStep: &zero}); err != nil {
			fail(err)
			return
		}
		_, _ = s.Meta.DeleteUserSessions(r.Context(), id, nil)
	default:
		wv.errorPage(400)
		return
	}
	audit()
	http.Redirect(w, r, wv.web.link+"admin/users/"+id, http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
}

func (s *Server) whAdminGC(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	s.Log.Info("web admin action", "actor", wv.sess.UserID, "action", "gc")
	if s.gc == nil {
		wv.errorPage(404)
		return
	}
	if _, err := s.gc.RunOnce(r.Context()); err != nil {
		s.Log.Error("web admin gc", "err", err)
		wv.render("admin", 200, struct {
			Users           int
			Version, Notice string
		}{Version: s.Version, Notice: "Garbage collection failed."})
		return
	}
	http.Redirect(w, r, wv.web.link+"admin?gc=1", http.StatusSeeOther)
}
