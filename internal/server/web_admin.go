// SPDX-License-Identifier: 0BSD

package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

func (s *Server) whAdminUser(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	s.renderAdminUser(wv, "", "", "")
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
			s.renderAdminUser(wv, "", "You cannot apply that action to your own account.", "")
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
				s.renderAdminUser(wv, "", "Quota must be a non-negative byte count.", "")
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
		s.invalidateUser(id)
	case "delete":
		if !wv.stepUp() {
			s.renderAdminUser(wv, "", "Enter your own password to confirm this action.", "")
			return
		}
		if err := s.Svc.AdminDeleteUser(r.Context(), p, id); err != nil {
			fail(err)
			return
		}
		_, _ = s.Meta.DeleteUserSessions(r.Context(), id, nil)
		s.invalidateUser(id)
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
		if !wv.stepUp() {
			s.renderAdminUser(wv, "", "Enter your own password to confirm this action.", "")
			return
		}
		s.audit(wv.r.Context(), wv.sess.UserID, action, "user", id, "")
		v := action == "grant_admin"
		if err := s.Meta.UpdateCredential(r.Context(), id, meta.CredentialPatch{Admin: &v}); err != nil {
			fail(err)
			return
		}
		// Role change kills existing sessions.
		_, _ = s.Meta.DeleteUserSessions(r.Context(), id, nil)
	case "reset_2fa":
		if !wv.stepUp() {
			s.renderAdminUser(wv, "", "Enter your own password to confirm this action.", "")
			return
		}
		no := false
		empty := []byte{}
		zero := int64(0)
		if err := s.Meta.UpdateCredential(r.Context(), id, meta.CredentialPatch{
			TOTPSecret: &empty, TOTPEnabled: &no, TOTPLastStep: &zero}); err != nil {
			fail(err)
			return
		}
		_, _ = s.Meta.DeleteUserSessions(r.Context(), id, nil)
	case "ban":
		reason := strings.TrimSpace(r.PostForm.Get("reason"))
		var until *time.Time
		if d, err := strconv.Atoi(r.PostForm.Get("days")); err == nil && d > 0 && d <= 3650 {
			t := s.now().Add(time.Duration(d) * 24 * time.Hour)
			until = &t
		}
		if err := s.Ban(r.Context(), wv.sess.UserID, id, reason, until, r.PostForm.Get("revoke_tokens") == "1"); err != nil {
			s.renderAdminUser(wv, "", "That account cannot be banned: it is your own account or the last administrator.", "")
			return
		}
	case "unban":
		if err := s.Unban(r.Context(), wv.sess.UserID, id); err != nil {
			fail(err)
			return
		}
	case "approve":
		if err := s.Approve(r.Context(), wv.sess.UserID, id); err != nil {
			fail(err)
			return
		}
	case "reject":
		if err := s.Reject(r.Context(), wv.sess.UserID, id); err != nil {
			fail(err)
			return
		}
		http.Redirect(w, r, wv.web.link+"admin/users?state=pending", http.StatusSeeOther) // #nosec G710 -- fixed route
		return
	case "unlock":
		if c, err := s.Meta.GetCredential(r.Context(), id); err == nil {
			s.web.userLock.ClearUnlock(c.Username)
		}
	case "set_password":
		if !wv.stepUp() {
			s.renderAdminUser(wv, "", "Enter your own password to confirm this action.", "")
			return
		}
		gen := r.PostForm.Get("generate") == "1"
		pw, err := s.AdminSetPassword(r.Context(), wv.sess.UserID, id, r.PostForm.Get("new_password"), gen)
		if err != nil {
			s.renderAdminUser(wv, "", "That password was rejected. Use at least 12 characters, or generate one.", "")
			return
		}
		if gen {
			s.renderAdminUser(wv, "The password was replaced and the account must change it at next sign-in.", "", pw)
			return
		}
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
	if err := s.RunGC(r.Context()); err != nil {
		s.Log.Error("web admin gc", "err", err)
		http.Redirect(w, r, wv.web.link+"admin/system?n=gcfail", http.StatusSeeOther) // #nosec G710 -- fixed route
		return
	}
	http.Redirect(w, r, wv.web.link+"admin/system?n=gc", http.StatusSeeOther) // #nosec G710 -- fixed route
}
