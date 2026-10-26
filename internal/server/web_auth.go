// SPDX-License-Identifier: 0BSD

package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
)

// errHashBusy is rendered as a styled 503.
var errHashBusy = auth.ErrHashBusy

const msgBadLogin = "Incorrect username or password."

func (s *Server) whHome(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if wv.path != "/" {
		wv.errorPage(404)
		return
	}
	if !s.Cfg.Web.Homepage {
		http.Redirect(w, r, wv.web.link+"login", http.StatusFound)
		return
	}
	// Homepage is indexable.
	w.Header().Del("X-Robots-Tag")
	wv.render("home", 200, struct{ Register bool }{s.Reg != nil && s.Reg.Mode != auth.RegClosed})
}

func (s *Server) whLoginGet(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	wv.loadSession()
	if wv.sess != nil && wv.sess.Kind == meta.SessionFull {
		http.Redirect(w, r, wv.web.link+"account", http.StatusSeeOther)
		return
	}
	s.renderLogin(wv, "", safeNext(r.URL.Query().Get("next")))
}

func (s *Server) renderLogin(wv *webReq, errMsg, next string) {
	wv.render("login", 200, struct {
		Error     string
		SignedOut bool
		Password  bool
		OIDC      bool
		OIDCLabel string
		Register  bool
		Next      string
	}{
		Error: errMsg, SignedOut: wv.r.URL.Query().Get("signed_out") == "1",
		Password: s.Cfg.Web.PasswordLogin,
		OIDC:     s.Cfg.Web.OIDC.Enabled, OIDCLabel: s.Cfg.Web.OIDC.Label,
		Register: s.Reg != nil && s.Reg.Mode != auth.RegClosed,
		Next:     next,
	})
}

func (s *Server) whLoginPost(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !s.Cfg.Web.PasswordLogin {
		wv.errorPage(404)
		return
	}
	wv.loadSession()
	if !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	next := safeNext(r.PostForm.Get("next"))
	username := strings.ToLower(strings.TrimSpace(r.PostForm.Get("username")))
	password := r.PostForm.Get("password")
	ip := s.clientIP(r)

	fail := func(reason string) {
		s.Met.WebLogin("failure")
		s.Log.Info("web login failed", "ip", ip, "reason", reason)
		s.audit(r.Context(), "", actLoginFail, "", "", fmt.Sprintf(`{"reason":%q,"ip":%q}`, reason, ip))
		s.renderLogin(wv, msgBadLogin, next)
	}

	if ok, after := s.web.loginLimiter.Allow(ip, 1); !ok {
		w.Header().Set("Retry-After", "60")
		_ = after
		fail("rate_limited")
		return
	}
	if s.web.userLock.locked(username) {
		s.audit(r.Context(), "", actLockout, "", "", "")
		fail("locked")
		return
	}
	cred, err := s.Meta.GetCredentialByUsername(r.Context(), username)
	if err != nil || cred.PasswordHash == "" {
		auth.VerifyDummy(password)
		s.web.userLock.fail(username)
		fail("no_credential")
		return
	}
	u, uerr := s.Meta.GetUser(r.Context(), cred.UserID)
	if uerr != nil || u.DeletedAt != nil {
		auth.VerifyDummy(password)
		s.web.userLock.fail(username)
		fail("disabled")
		return
	}
	ok, rehash, err := auth.VerifyPassword(cred.PasswordHash, password)
	if err != nil {
		if errors.Is(err, errHashBusy) {
			w.Header().Set("Retry-After", "5")
			wv.errorPage(503)
			return
		}
		fail("verify_error")
		return
	}
	if !ok {
		s.web.userLock.fail(username)
		fail("bad_password")
		return
	}
	if rehash {
		if nh, err := auth.HashPassword(password); err == nil {
			_ = s.Meta.UpdateCredential(r.Context(), cred.UserID, meta.CredentialPatch{PasswordHash: &nh})
		}
	}
	s.web.userLock.reset(username)
	s.audit(r.Context(), u.ID, actLoginOK, "user", u.ID, fmt.Sprintf(`{"ip":%q}`, ip))

	// moderation states show a fixed page, never a session
	st, stErr := s.Meta.GetUserStatus(r.Context(), u.ID)
	if stErr != nil && u.Disabled {
		fail("disabled")
		return
	}
	if stErr == nil {
		switch st.State {
		case "banned":
			msg := "This account is suspended."
			if s.siteVals().ShowBanReason && st.Reason != "" {
				msg = "This account is suspended: " + st.Reason
			}
			s.renderLogin(wv, msg, next)
			return
		case "pending":
			s.renderLogin(wv, "Your account is waiting for approval.", next)
			return
		}
	}

	if cred.TOTPEnabled {
		if err := wv.createSession(u.ID, meta.SessionPending, meta.SessionMethodPassword,
			false, s.Cfg.Web.Session.PendingTTL.Duration()); err != nil {
			s.Log.Error("web session create", "err", err)
			wv.errorPage(500)
			return
		}
		http.Redirect(w, r, wv.web.link+"login/2fa?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	if err := wv.createSession(u.ID, meta.SessionFull, meta.SessionMethodPassword,
		cred.Admin, s.Cfg.Web.Session.Absolute.Duration()); err != nil {
		s.Log.Error("web session create", "err", err)
		wv.errorPage(500)
		return
	}
	s.Met.WebLogin("password")
	s.Log.Info("web login", "user", u.ID, "method", "password", "ip", ip)
	http.Redirect(w, r, wv.web.link+strings.TrimPrefix(next, "/"), http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
}

// requirePending enforces the pending 2FA session.
func (wv *webReq) requirePending() bool {
	wv.loadSession()
	if wv.sess == nil || wv.sess.Kind != meta.SessionPending {
		http.Redirect(wv.w, wv.r, wv.web.link+"login", http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
		return false
	}
	return true
}

func (s *Server) wh2faGet(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requirePending() {
		return
	}
	wv.render("2fa", 200, struct {
		Error  string
		Notice string
		Next   string
	}{Next: safeNext(r.URL.Query().Get("next"))})
}

func (s *Server) wh2faPost(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requirePending() {
		return
	}
	if !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	next := safeNext(r.PostForm.Get("next"))
	renderErr := func(msg string) {
		wv.render("2fa", 200, struct {
			Error  string
			Notice string
			Next   string
		}{Error: msg, Next: next})
	}
	maxAtt := s.Cfg.Web.Session.Max2FAAttempts
	bump := func() bool { // true means still allowed to retry
		n, err := s.Meta.BumpWebSessionAttempts(r.Context(), wv.sess.IDHash)
		if err != nil {
			wv.errorPage(500)
			return false
		}
		if n >= maxAtt {
			_ = s.Meta.DeleteWebSession(r.Context(), wv.sess.IDHash)
			http.Redirect(w, r, wv.web.link+"login", http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
			return false
		}
		return true
	}
	cred, err := s.Meta.GetCredential(r.Context(), wv.sess.UserID)
	if err != nil || !cred.TOTPEnabled {
		renderErr(msgBadLogin)
		return
	}
	// Recovery code path.
	if rc := r.PostForm.Get("recovery"); rc != "" {
		rem, err := s.Meta.ConsumeRecoveryCode(r.Context(), wv.sess.UserID, auth.HashRecovery(rc))
		if err != nil {
			if !bump() {
				return
			}
			renderErr(msgBadLogin)
			return
		}
		uid := wv.sess.UserID
		wv.finish2fa(w, r, cred)
		s.Met.WebLogin("recovery")
		s.Log.Info("web recovery code used", "user", uid, "remaining", rem)
		http.Redirect(w, r, wv.web.link+"account/security?used_recovery=1&rc="+strconv.Itoa(rem), http.StatusSeeOther)
		return
	}
	code := r.PostForm.Get("code")
	plain, err := auth.Open(wv.sessKey(), auth.SealTOTPSecret, []byte(cred.UserID), cred.TOTPSecret)
	if err != nil {
		renderErr(msgBadLogin)
		return
	}
	step, ok := auth.VerifyTOTP(plain, code, s.Clock())
	if !ok {
		if !bump() {
			return
		}
		renderErr(msgBadLogin)
		return
	}
	// Replay protection: accept only a strictly newer step.
	adv, err := s.Meta.AdvanceTOTPStep(r.Context(), wv.sess.UserID, step)
	if err != nil || !adv {
		if !bump() {
			return
		}
		renderErr(msgBadLogin)
		return
	}
	wv.finish2fa(w, r, cred)
	s.Met.WebLogin("totp")
	http.Redirect(w, r, wv.web.link+strings.TrimPrefix(next, "/"), http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
}

// sessKey returns the raw web secret.
func (wv *webReq) sessKey() []byte { return []byte(wv.s.Cfg.Web.Secret) }

// finish2fa replaces the pending session with a fresh full session.
func (wv *webReq) finish2fa(w http.ResponseWriter, r *http.Request, cred meta.WebCredential) {
	_ = wv.s.Meta.DeleteWebSession(r.Context(), wv.sess.IDHash)
	wv.sess = nil
	wv.sessDone = true
	_ = wv.createSession(wv.user.ID, meta.SessionFull, meta.SessionMethodPassword,
		cred.Admin, wv.s.Cfg.Web.Session.Absolute.Duration())
	wv.s.Log.Info("web login", "user", wv.user.ID, "method", "password+2fa", "ip", wv.s.clientIP(r))
}

func (s *Server) whRegisterGet(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if s.Reg == nil || s.Reg.Mode == auth.RegClosed {
		wv.errorPage(404)
		return
	}
	wv.render("register", 200, struct {
		Error  string
		Invite bool
	}{Invite: s.Reg.Mode == auth.RegInvite})
}

func (s *Server) whRegisterPost(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if s.Reg == nil || s.Reg.Mode == auth.RegClosed {
		wv.errorPage(404)
		return
	}
	wv.loadSession()
	if !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	renderErr := func(msg string) {
		wv.render("register", 200, struct {
			Error  string
			Invite bool
		}{Error: msg, Invite: s.Reg.Mode == auth.RegInvite})
	}
	username := strings.ToLower(strings.TrimSpace(r.PostForm.Get("username")))
	if !validUsername(username) {
		renderErr("Usernames use lowercase letters, digits, dot, dash, and underscore (1 to 64 characters).")
		return
	}
	pw, pw2 := r.PostForm.Get("password"), r.PostForm.Get("password2")
	if pw != pw2 {
		renderErr("Passwords do not match.")
		return
	}
	if err := auth.CheckPasswordPolicy(pw, username); err != nil {
		renderErr("The password does not meet the policy (minimum 12 characters, not equal to the username).")
		return
	}
	u, err := s.Reg.RegisterNoToken(r.Context(), s.clientIP(r), r.PostForm.Get("invite"))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			wv.errorPage(429)
		case errors.Is(err, auth.ErrBadInvite):
			renderErr("The invite code is not valid.")
		default:
			s.Log.Error("web register", "err", err)
			renderErr("Registration failed.")
		}
		return
	}
	ph, err := auth.HashPassword(pw)
	if err != nil {
		if errors.Is(err, errHashBusy) {
			w.Header().Set("Retry-After", "5")
			wv.errorPage(503)
			return
		}
		renderErr("Registration failed.")
		return
	}
	err = s.Meta.CreateCredential(r.Context(), meta.WebCredential{
		UserID: u.ID, Username: username, PasswordHash: ph})
	if errors.Is(err, meta.ErrExists) {
		renderErr("That username is taken.")
		return
	}
	if err != nil {
		s.Log.Error("web register credential", "err", err)
		renderErr("Registration failed.")
		return
	}
	s.Log.Info("web registered", "user", u.ID)
	if u.Disabled {
		renderErr("Your account is waiting for approval.")
		return
	}
	http.Redirect(w, r, wv.web.link+"login", http.StatusSeeOther)
}

func validUsername(u string) bool {
	if len(u) < 1 || len(u) > 64 {
		return false
	}
	for _, r := range u {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_'
		if !ok {
			return false
		}
	}
	return true
}

func (s *Server) whLogout(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	wv.loadSession()
	if !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	if wv.sess != nil {
		_ = s.Meta.DeleteWebSession(r.Context(), wv.sess.IDHash)
		s.Log.Info("web logout", "user", wv.sess.UserID)
	}
	wv.setCookie(sessCookie, "", -1, false)
	w.Header().Set("Clear-Site-Data", `"cache"`)
	http.Redirect(w, r, wv.web.link+"login?signed_out=1", http.StatusSeeOther)
}
