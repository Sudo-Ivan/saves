// SPDX-License-Identifier: 0BSD

package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/settings"
)

// accessView is the invites and IP block page.
type accessView struct {
	Tabs          []adminTab
	Invites       []meta.Invite
	Blocks        []meta.IPBlock
	NewCode       string
	Notice, Error string
	MyIP          string
}

func (s *Server) renderAccess(wv *webReq, notice, errMsg, code string) {
	v := accessView{Tabs: adminTabs(wv.web.link, "access"), NewCode: code, Notice: notice, Error: errMsg,
		MyIP: netx.ClientIPReal(wv.r, s.trustedCIDRs(), s.Cfg.Proxy.RealIPHeader).String()}
	v.Invites, _ = s.Meta.ListInvites(wv.r.Context())
	v.Blocks, _ = s.Meta.ListIPBlocks(wv.r.Context())
	wv.render("admin_access", 200, v)
}

func (s *Server) whAdminAccess(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	notice := map[string]string{"revoked": "Invite revoked.", "unblocked": "Block removed.", "blocked": "Block added."}[r.URL.Query().Get("n")]
	s.renderAccess(wv, notice, "", "")
}

func (s *Server) whAdminInviteCreate(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	code := "inv_" + hex.EncodeToString(raw)
	maxUses, _ := strconv.Atoi(r.PostForm.Get("max_uses"))
	if maxUses < 0 || maxUses > 100000 {
		maxUses = 1
	}
	var exp *time.Time
	if d, err := strconv.Atoi(r.PostForm.Get("days")); err == nil && d > 0 && d <= 3650 {
		t := s.now().Add(time.Duration(d) * 24 * time.Hour)
		exp = &t
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if len(label) > 80 {
		label = label[:80]
	}
	id, _ := meta.NewID(s.now())
	now := s.now()
	err := s.Meta.CreateInvite(r.Context(), meta.Invite{ID: id, CodeHash: sha256.Sum256([]byte(code)),
		CodePrefix: code[:6], Label: label, MaxUses: maxUses, CreatedBy: wv.sess.UserID, CreatedAt: &now, ExpiresAt: exp})
	if err != nil {
		s.renderAccess(wv, "", "The invite could not be created.", "")
		return
	}
	s.audit(r.Context(), wv.sess.UserID, "invite_create", "invite", id, "")
	s.renderAccess(wv, "Invite created. Copy the code now, it is not shown again.", "", code)
}

func (s *Server) whAdminInviteRevoke(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	id := r.PathValue("id")
	if err := s.Meta.RevokeInvite(r.Context(), id); err == nil {
		s.audit(r.Context(), wv.sess.UserID, "invite_revoke", "invite", id, "")
	}
	http.Redirect(w, r, wv.web.link+"admin/access?n=revoked", http.StatusSeeOther) // #nosec G710 -- fixed route
}

func (s *Server) whAdminBlockCreate(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	var exp *time.Time
	if d, err := strconv.Atoi(r.PostForm.Get("days")); err == nil && d > 0 && d <= 3650 {
		t := s.now().Add(time.Duration(d) * 24 * time.Hour)
		exp = &t
	}
	ctx := ctxWithIP(r.Context(), netx.ClientIPReal(r, s.trustedCIDRs(), s.Cfg.Proxy.RealIPHeader))
	if err := s.AddIPBlock(ctx, wv.sess.UserID, strings.TrimSpace(r.PostForm.Get("cidr")), strings.TrimSpace(r.PostForm.Get("reason")), exp); err != nil {
		s.renderAccess(wv, "", problemMessage(err), "")
		return
	}
	s.audit(r.Context(), wv.sess.UserID, "ip_block_add", "ip", r.PostForm.Get("cidr"), "")
	http.Redirect(w, r, wv.web.link+"admin/access?n=blocked", http.StatusSeeOther) // #nosec G710 -- fixed route
}

func (s *Server) whAdminBlockDelete(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	if err := s.RemoveIPBlock(r.Context(), r.PathValue("id")); err == nil {
		s.audit(r.Context(), wv.sess.UserID, "ip_block_remove", "ip", r.PathValue("id"), "")
	}
	http.Redirect(w, r, wv.web.link+"admin/access?n=unblocked", http.StatusSeeOther) // #nosec G710 -- fixed route
}

type settingRow struct {
	settings.Field
	Value      string
	Bool       bool
	Overridden bool
	By         string
}

type settingGroup struct {
	Title string
	Rows  []settingRow
}

type settingsView struct {
	Tabs          []adminTab
	Groups        []settingGroup
	Notice, Error string
	Available     bool
}

var groupTitles = []struct{ prefix, title string }{
	{"site.", "Site"}, {"registration.", "Registration"}, {"maintenance.", "Maintenance"},
	{"quota.", "Quotas"}, {"token.", "API tokens"}, {"web.", "Sessions and sign-in"}, {"auth.", "Authentication"},
}

func (s *Server) renderSettings(wv *webReq, notice, errMsg string) {
	v := settingsView{Tabs: adminTabs(wv.web.link, "settings"), Notice: notice, Error: errMsg}
	mgr, ok := s.settings.(*settings.Manager)
	if !ok {
		wv.render("admin_settings", 200, v)
		return
	}
	v.Available = true
	raw, _ := json.Marshal(mgr.Effective())
	var vals map[string]json.RawMessage
	_ = json.Unmarshal(raw, &vals)
	over := map[string]settings.Override{}
	for _, o := range mgr.Overrides() {
		over[o.Key] = o
	}
	for _, g := range groupTitles {
		grp := settingGroup{Title: g.title}
		for _, f := range settings.Schema() {
			if !strings.HasPrefix(f.Key, g.prefix) || f.Type == "tiers" {
				continue
			}
			row := settingRow{Field: f}
			var str string
			if json.Unmarshal(vals[f.Key], &str) == nil {
				row.Value = str
			} else {
				row.Value = strings.Trim(string(vals[f.Key]), `"`)
			}
			row.Bool = row.Value == "true"
			if o, ok := over[f.Key]; ok {
				row.Overridden, row.By = true, o.UpdatedBy
			}
			grp.Rows = append(grp.Rows, row)
		}
		if len(grp.Rows) > 0 {
			v.Groups = append(v.Groups, grp)
		}
	}
	wv.render("admin_settings", 200, v)
}

func (s *Server) whAdminSettings(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	notice := map[string]string{"saved": "Settings saved and applied.", "reset": "Setting reset to the file default.", "same": "Nothing changed."}[r.URL.Query().Get("n")]
	s.renderSettings(wv, notice, "")
}

func (s *Server) whAdminSettingsSave(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	mgr, ok := s.settings.(*settings.Manager)
	if !ok {
		wv.errorPage(404)
		return
	}
	if !wv.stepUp() {
		s.renderSettings(wv, "", "Enter your own password to save settings.")
		return
	}
	raw, _ := json.Marshal(mgr.Effective())
	var cur map[string]json.RawMessage
	_ = json.Unmarshal(raw, &cur)
	patch := map[string]json.RawMessage{}
	for _, f := range settings.Schema() {
		if f.Type == "tiers" {
			continue
		}
		in := strings.TrimSpace(r.PostForm.Get("f:" + f.Key))
		var nv json.RawMessage
		switch f.Type {
		case "bool":
			nv, _ = json.Marshal(r.PostForm.Get("f:"+f.Key) == "1")
		case "int":
			n, err := strconv.Atoi(in)
			if err != nil {
				s.renderSettings(wv, "", f.Label+" must be a whole number.")
				return
			}
			nv, _ = json.Marshal(n)
		case "float":
			n, err := strconv.ParseFloat(in, 64)
			if err != nil {
				s.renderSettings(wv, "", f.Label+" must be a number.")
				return
			}
			nv, _ = json.Marshal(n)
		default:
			nv, _ = json.Marshal(in)
		}
		if string(nv) != string(cur[f.Key]) {
			patch[f.Key] = nv
		}
	}
	if len(patch) == 0 {
		http.Redirect(w, r, wv.web.link+"admin/settings?n=same", http.StatusSeeOther) // #nosec G710 -- fixed route
		return
	}
	if _, err := mgr.Update(r.Context(), wv.sess.UserID, patch); err != nil {
		s.renderSettings(wv, "", "A value was rejected. Check the highlighted fields and limits.")
		return
	}
	http.Redirect(w, r, wv.web.link+"admin/settings?n=saved", http.StatusSeeOther) // #nosec G710 -- fixed route
}

func (s *Server) whAdminSettingsReset(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	if mgr, ok := s.settings.(*settings.Manager); ok {
		_ = mgr.Reset(r.Context(), wv.sess.UserID, r.PostForm.Get("key"))
	}
	http.Redirect(w, r, wv.web.link+"admin/settings?n=reset", http.StatusSeeOther) // #nosec G710 -- fixed route
}

type auditView struct {
	Tabs              []adminTab
	Events            []meta.AuditEvent
	Q, Action, Target string
	Next, CSV         string
	Actions           []string
}

var auditActions = []string{"login_ok", "login_fail", "lockout", "logout", "register", "ban", "unban", "approve", "reject",
	"admin.fsck", "admin.backup", "invite_create", "invite_revoke", "ip_block_add", "ip_block_remove", "settings.change"}

func auditFilter(q url.Values) meta.AuditFilter {
	f := meta.AuditFilter{Action: q.Get("action"), TargetID: q.Get("target"), Query: q.Get("q")}
	if len(f.Query) > 100 {
		f.Query = f.Query[:100]
	}
	return f
}

func (s *Server) whAdminAudit(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	q := r.URL.Query()
	f := auditFilter(q)
	ev, next, err := s.Meta.ListAudit(r.Context(), f, q.Get("cursor"), 50)
	if err != nil {
		wv.errorPage(400)
		return
	}
	v := auditView{Tabs: adminTabs(wv.web.link, "audit"), Events: ev, Q: f.Query, Action: f.Action, Target: f.TargetID, Actions: auditActions}
	base := url.Values{}
	for _, k := range []string{"q", "action", "target"} {
		if x := q.Get(k); x != "" {
			base.Set(k, x)
		}
	}
	v.CSV = wv.web.link + "admin/audit.csv?" + base.Encode()
	if next != "" {
		base.Set("cursor", next)
		v.Next = wv.web.link + "admin/audit?" + base.Encode()
	}
	wv.render("admin_audit", 200, v)
}

func (s *Server) whAdminAuditCSV(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	f := auditFilter(r.URL.Query())
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="audit.csv"`)
	h.Set("Cache-Control", "no-store")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "action", "actor", "target_type", "target", "address", "detail"})
	cursor := ""
	for n := 0; n < 20; n++ {
		ev, next, err := s.Meta.ListAudit(r.Context(), f, cursor, 200)
		if err != nil {
			break
		}
		for _, e := range ev {
			_ = cw.Write([]string{e.At.UTC().Format(time.RFC3339), csvCell(e.Action), csvCell(e.ActorID), csvCell(e.TargetType),
				csvCell(e.TargetID), csvCell(e.IP), csvCell(e.Detail)})
		}
		if next == "" {
			break
		}
		cursor = next
	}
	cw.Flush()
}
