// SPDX-License-Identifier: 0BSD

package server

import (
	"encoding/hex"
	"errors"
	"image/color"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/boombuler/barcode/qr"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func (s *Server) whAccount(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	u, usage, err := s.Svc.Me(r.Context(), wv.principal())
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	apps, err := s.Svc.ListApps(r.Context(), wv.principal())
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	username := ""
	if wv.cred != nil {
		username = wv.cred.Username
	}
	wv.render("account", 200, struct {
		Username string
		Tier     string
		Usage    meta.Usage
		Apps     []meta.AppSummary
		Notice   string
	}{Username: username, Tier: u.Tier, Usage: usage, Apps: apps})
}

func (s *Server) whApp(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	app := r.PathValue("app")
	slots, err := s.Svc.ListSlots(r.Context(), wv.principal(), app)
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	wv.render("app", 200, struct {
		App   string
		Slots []meta.Slot
	}{App: app, Slots: slots})
}

func (s *Server) whSlot(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	app, slot := r.PathValue("app"), r.PathValue("slot")
	snaps, _, err := s.Svc.ListSnapshots(r.Context(), wv.principal(), app, slot, "", 100)
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	head := ""
	if sl, err := s.Svc.GetSlot(r.Context(), wv.principal(), app, slot); err == nil {
		head = sl.HeadSnapshotID
	}
	wv.render("slot", 200, struct {
		App       string
		Slot      string
		Head      string
		Snapshots []meta.Snapshot
	}{App: app, Slot: slot, Head: head, Snapshots: snaps})
}

// serveArchive streams the snapshot tar, shared by the API and web.
func (s *Server) serveArchive(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="archive.tar"`)
	w.WriteHeader(200)
	if err := s.Svc.WriteArchive(r.Context(), p, r.PathValue("app"), r.PathValue("slot"), r.PathValue("id"), w); err != nil {
		s.Log.Error("archive", "err", err)
	}
}

func (s *Server) whArchive(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	s.serveArchive(w, r, wv.principal())
}

func (s *Server) whSnapshotDeleteGet(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	app, slot, id := r.PathValue("app"), r.PathValue("slot"), r.PathValue("id")
	wv.render("confirm", 200, struct {
		Heading string
		Warning string
		URL     string
		Back    string
	}{
		Heading: "Delete snapshot",
		Warning: "Snapshot " + id + " will be deleted permanently.",
		URL:     wv.web.link + "account/apps/" + app + "/slots/" + slot + "/snapshots/" + id + "/delete",
		Back:    wv.web.link + "account/apps/" + app + "/slots/" + slot,
	})
}

func (s *Server) whSnapshotDeletePost(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	app, slot, id := r.PathValue("app"), r.PathValue("slot"), r.PathValue("id")
	if err := s.Svc.DeleteSnapshot(r.Context(), wv.principal(), app, slot, id); err != nil {
		s.webServiceError(wv, err)
		return
	}
	http.Redirect(w, r, wv.web.link+"account/apps/"+url.PathEscape(app)+"/slots/"+slot, http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
}

func (s *Server) whSlotDeleteGet(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	app, slot := r.PathValue("app"), r.PathValue("slot")
	wv.render("confirm", 200, struct {
		Heading string
		Warning string
		URL     string
		Back    string
	}{
		Heading: "Delete slot",
		Warning: "Slot " + slot + " and all its snapshots will be deleted permanently.",
		URL:     wv.web.link + "account/apps/" + app + "/slots/" + slot + "/delete",
		Back:    wv.web.link + "account/apps/" + app + "/slots/" + slot,
	})
}

func (s *Server) whSlotDeletePost(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	app, slot := r.PathValue("app"), r.PathValue("slot")
	if err := s.Svc.DeleteSlot(r.Context(), wv.principal(), app, slot); err != nil {
		s.webServiceError(wv, err)
		return
	}
	http.Redirect(w, r, wv.web.link+"account/apps/"+app, http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
}

// sessView is one row of the session table.
type sessView struct {
	meta.WebSession
	Key     string
	Current bool
}

func (s *Server) whSecurity(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	s.renderSecurity(wv, "", "")
}

// renderSecurity renders the security page with optional messages.
func (s *Server) renderSecurity(wv *webReq, notice, errMsg string) {
	r := wv.r
	var sessions []sessView
	list, err := s.Meta.ListWebSessions(r.Context(), wv.sess.UserID)
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	for _, ws := range list {
		if ws.Kind != meta.SessionFull {
			continue
		}
		sessions = append(sessions, sessView{
			WebSession: ws,
			Key:        hex.EncodeToString(ws.IDHash[:]),
			Current:    ws.IDHash == wv.sess.IDHash,
		})
	}
	totp := wv.cred != nil && wv.cred.TOTPEnabled
	recoveryLeft := -1
	if rc := r.URL.Query().Get("rc"); rc != "" {
		if n, err := strconv.Atoi(rc); err == nil && n >= 0 && n <= auth.RecoveryCount {
			recoveryLeft = n
		}
	}
	if r.URL.Query().Get("used_recovery") == "1" && notice == "" {
		notice = "You signed in with a recovery code."
		if recoveryLeft >= 0 {
			notice = "You signed in with a recovery code; " + strconv.Itoa(recoveryLeft) + " codes remain."
		}
	}
	wv.render("security", 200, struct {
		Username     string
		MustChange   bool
		TOTPEnabled  bool
		CanTOTP      bool
		RecoveryLeft int
		Sessions     []sessView
		Notice       string
		Error        string
	}{
		Username: credName(wv.cred), MustChange: wv.cred != nil && wv.cred.MustChange,
		TOTPEnabled: totp, CanTOTP: wv.sess.Method == meta.SessionMethodPassword && wv.cred != nil && wv.cred.PasswordHash != "",
		RecoveryLeft: recoveryLeft, Sessions: sessions, Notice: notice, Error: errMsg,
	})
}

func credName(c *meta.WebCredential) string {
	if c == nil {
		return ""
	}
	return c.Username
}

// verifyCurrentPassword checks the current password for sensitive
// actions. Returns false after rendering the error.
func (wv *webReq) verifyCurrentPassword(pw string) bool {
	if wv.cred == nil || wv.cred.PasswordHash == "" {
		return false
	}
	ok, _, err := auth.VerifyPassword(wv.cred.PasswordHash, pw)
	return err == nil && ok
}

func (s *Server) whPasswordChange(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	if wv.cred == nil || wv.cred.PasswordHash == "" {
		wv.errorPage(403)
		return
	}
	cur, pw, pw2 := r.PostForm.Get("current"), r.PostForm.Get("new"), r.PostForm.Get("new2")
	if !wv.verifyCurrentPassword(cur) {
		s.renderSecurity(wv, "", "Incorrect current password.")
		return
	}
	if pw != pw2 {
		s.renderSecurity(wv, "", "Passwords do not match.")
		return
	}
	if err := auth.CheckPasswordPolicy(pw, wv.cred.Username); err != nil {
		s.renderSecurity(wv, "", "The password does not meet the policy (minimum 12 characters, not equal to the username).")
		return
	}
	ph, err := auth.HashPassword(pw)
	if err != nil {
		if errors.Is(err, auth.ErrHashBusy) {
			w.Header().Set("Retry-After", "5")
			wv.errorPage(503)
			return
		}
		s.renderSecurity(wv, "", "Password change failed.")
		return
	}
	no := false
	err = s.Meta.UpdateCredential(r.Context(), wv.sess.UserID, meta.CredentialPatch{
		PasswordHash: &ph, MustChange: &no})
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	// A password change kills every other session.
	_, _ = s.Meta.DeleteUserSessions(r.Context(), wv.sess.UserID, &wv.sess.IDHash)
	s.Log.Info("web password changed", "user", wv.sess.UserID)
	http.Redirect(w, r, wv.web.link+"account/security", http.StatusSeeOther)
}

// qrRect is one dark module of a QR matrix.
type qrRect struct{ X, Y int }

// qrMatrix renders content as module rects for inline SVG output.
func qrMatrix(content string) ([]qrRect, int, error) {
	code, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return nil, 0, err
	}
	b := code.Bounds()
	size := b.Dx() + 8 // quiet zone of 4 modules per side
	var rects []qrRect
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := code.At(x, y)
			r_, g_, b_, a := color.Color(c).RGBA()
			if a > 0 && r_ == 0 && g_ == 0 && b_ == 0 {
				rects = append(rects, qrRect{X: x - b.Min.X + 4, Y: y - b.Min.Y + 4})
			}
		}
	}
	return rects, size, nil
}

func (s *Server) wh2faSetupGet(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	if wv.cred == nil || wv.cred.PasswordHash == "" || wv.sess.Method != meta.SessionMethodPassword {
		wv.errorPage(404)
		return
	}
	if wv.cred.TOTPEnabled {
		http.Redirect(w, r, wv.web.link+"account/security", http.StatusSeeOther)
		return
	}
	s.render2faSetup(wv, nil, "", "")
}

// render2faSetup draws the enrollment page. sealed is the sealed
// secret carried in the hidden form field.
func (s *Server) render2faSetup(wv *webReq, secret []byte, sealed, errMsg string) {
	if len(secret) == 0 {
		var err error
		secret, err = auth.NewTOTPSecret()
		if err != nil {
			wv.errorPage(500)
			return
		}
		sealed, err = auth.SealString(wv.sessKey(), auth.SealTOTPSecret, wv.sess.UserID,
			strconv.FormatInt(wv.s.Clock().Add(15*time.Minute).Unix(), 10)+":"+string(secret))
		if err != nil {
			wv.errorPage(500)
			return
		}
	}
	uri := auth.TOTPURI(wv.s.Cfg.Web.InstanceName, credName(wv.cred), secret)
	rects, size, err := qrMatrix(uri)
	if err != nil {
		wv.errorPage(500)
		return
	}
	wv.render("2fa_setup", 200, struct {
		Error     string
		Done      bool
		SecretB32 string
		URI       string
		Sealed    string
		QR        []qrRect
		QRSize    int
		Codes     []string
	}{Error: errMsg, SecretB32: auth.TOTPSecretBase32(secret), URI: uri, Sealed: sealed,
		QR: rects, QRSize: size})
}

func (s *Server) wh2faSetupPost(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	if wv.cred == nil || wv.cred.PasswordHash == "" || wv.cred.TOTPEnabled {
		http.Redirect(w, r, wv.web.link+"account/security", http.StatusSeeOther)
		return
	}
	sealed := r.PostForm.Get("enroll")
	raw, err := auth.OpenString(wv.sessKey(), auth.SealTOTPSecret, wv.sess.UserID, sealed)
	if err != nil {
		s.render2faSetup(wv, nil, "", "The enrollment expired. Start again.")
		return
	}
	exp, sec, ok := strings.Cut(raw, ":")
	expN, perr := strconv.ParseInt(exp, 10, 64)
	if !ok || perr != nil || wv.s.Clock().Unix() > expN {
		s.render2faSetup(wv, nil, "", "The enrollment expired. Start again.")
		return
	}
	secret := []byte(sec)
	if len(secret) != auth.TOTPSecretLen {
		s.render2faSetup(wv, nil, "", "The enrollment expired. Start again.")
		return
	}
	code := strings.TrimSpace(r.PostForm.Get("code"))
	step, ok := auth.VerifyTOTP(secret, code, s.Clock())
	if !ok {
		s.render2faSetup(wv, secret, sealed, "Incorrect code.")
		return
	}
	// Seal the raw secret for storage; the enroll blob also carried an
	// expiry so it cannot be reused directly.
	sealedBytes, err := auth.Seal(wv.sessKey(), auth.SealTOTPSecret, []byte(wv.sess.UserID), secret)
	if err != nil {
		s.render2faSetup(wv, secret, sealed, "The enrollment expired. Start again.")
		return
	}
	yes := true
	if err := s.Meta.UpdateCredential(r.Context(), wv.sess.UserID, meta.CredentialPatch{
		TOTPSecret: &sealedBytes, TOTPEnabled: &yes}); err != nil {
		s.webServiceError(wv, err)
		return
	}
	_, _ = s.Meta.AdvanceTOTPStep(r.Context(), wv.sess.UserID, step)
	codes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		wv.errorPage(500)
		return
	}
	var hashes [][32]byte
	for _, c := range codes {
		hashes = append(hashes, auth.HashRecovery(c))
	}
	if err := s.Meta.SetRecoveryCodes(r.Context(), wv.sess.UserID, hashes); err != nil {
		s.webServiceError(wv, err)
		return
	}
	s.Log.Info("web totp enabled", "user", wv.sess.UserID)
	wv.render("2fa_setup", 200, struct {
		Error     string
		Done      bool
		SecretB32 string
		URI       string
		Sealed    string
		QR        []qrRect
		QRSize    int
		Codes     []string
	}{Done: true, Codes: codes})
}

func (s *Server) wh2faDisable(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	if wv.cred == nil || wv.cred.PasswordHash == "" || !wv.verifyCurrentPassword(r.PostForm.Get("current")) {
		s.renderSecurity(wv, "", "Incorrect current password.")
		return
	}
	no := false
	empty := []byte{}
	zero := int64(0)
	if err := s.Meta.UpdateCredential(r.Context(), wv.sess.UserID, meta.CredentialPatch{
		TOTPSecret: &empty, TOTPEnabled: &no, TOTPLastStep: &zero}); err != nil {
		s.webServiceError(wv, err)
		return
	}
	if err := s.Meta.SetRecoveryCodes(r.Context(), wv.sess.UserID, nil); err != nil {
		s.webServiceError(wv, err)
		return
	}
	s.Log.Info("web totp disabled", "user", wv.sess.UserID)
	http.Redirect(w, r, wv.web.link+"account/security", http.StatusSeeOther)
}

func (s *Server) whRecoveryRegen(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	if wv.cred == nil || wv.cred.PasswordHash == "" || !wv.verifyCurrentPassword(r.PostForm.Get("current")) {
		s.renderSecurity(wv, "", "Incorrect current password.")
		return
	}
	codes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		wv.errorPage(500)
		return
	}
	var hashes [][32]byte
	for _, c := range codes {
		hashes = append(hashes, auth.HashRecovery(c))
	}
	if err := s.Meta.SetRecoveryCodes(r.Context(), wv.sess.UserID, hashes); err != nil {
		s.webServiceError(wv, err)
		return
	}
	s.Log.Info("web recovery codes regenerated", "user", wv.sess.UserID)
	wv.render("recovery", 200, struct{ Codes []string }{Codes: codes})
}

func (s *Server) whSessionRevoke(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	h, err := hex.DecodeString(r.PathValue("hash"))
	if err != nil || len(h) != 32 {
		wv.errorPage(404)
		return
	}
	var h32 [32]byte
	copy(h32[:], h)
	ws, err := s.Meta.GetWebSession(r.Context(), h32)
	if err != nil || ws.UserID != wv.sess.UserID {
		wv.errorPage(404)
		return
	}
	if err := s.Meta.DeleteWebSession(r.Context(), h32); err != nil {
		s.webServiceError(wv, err)
		return
	}
	s.Log.Info("web session revoked", "user", wv.sess.UserID)
	s.audit(wv.r.Context(), wv.sess.UserID, actSessRevoke, "session", "", "")
	http.Redirect(w, r, wv.web.link+"account/security", http.StatusSeeOther)
}

func (s *Server) whSessionRevokeOthers(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	if _, err := s.Meta.DeleteUserSessions(r.Context(), wv.sess.UserID, &wv.sess.IDHash); err != nil {
		s.webServiceError(wv, err)
		return
	}
	s.Log.Info("web sessions revoked", "user", wv.sess.UserID)
	s.audit(wv.r.Context(), wv.sess.UserID, actSessRevoke, "session", "all", "")
	http.Redirect(w, r, wv.web.link+"account/security", http.StatusSeeOther)
}

// webServiceError maps a service error onto the styled pages.
func (s *Server) webServiceError(wv *webReq, err error) {
	var code int
	var prob *api.Problem
	switch {
	case errors.As(err, &prob):
		code = prob.Status
	case errors.Is(err, meta.ErrNotFound):
		code = 404
	case errors.Is(err, auth.ErrForbidden):
		code = 403
	case errors.Is(err, auth.ErrRateLimited):
		code = 429
	default:
		s.Log.Error("web service error", "err", err, "path", wv.path)
		code = 500
	}
	wv.errorPage(code)
}
