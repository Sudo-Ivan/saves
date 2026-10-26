// SPDX-License-Identifier: 0BSD

package server

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

// stepUp asks an administrator to prove it is still them before a
// destructive action. OIDC sessions have no local password and pass.
func (wv *webReq) stepUp() bool {
	if wv.sess.Method == meta.SessionMethodOIDC {
		return true
	}
	return wv.verifyCurrentPassword(wv.r.PostForm.Get("confirm_password"))
}

const adminPageSize = 25

type adminUsersView struct {
	Tabs                 []adminTab
	Rows                 []userRow
	Total                int
	Q, State, Tier, Sort string
	Desc, AdminOnly      bool
	Page, Pages          int
	PrevHref, NextHref   string
	States               []stateOption
	Pending              int64
}

type stateOption struct {
	Value, Label string
	Selected     bool
}

type userRow struct {
	meta.AdminUserRow
	Name, Last, QuotaText string
	UsedPct               int
}

func (s *Server) whAdminUsers(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	q := r.URL.Query()
	f := meta.UserFilter{Query: q.Get("q"), State: q.Get("state"), Tier: q.Get("tier"),
		Sort: q.Get("sort"), Desc: q.Get("dir") != "asc", AdminOnly: q.Get("admins") == "1"}
	switch f.Sort {
	case "created", "used", "name", "last_active":
	default:
		f.Sort = "created"
	}
	switch f.State {
	case "active", "disabled", "banned", "pending", "deleted", "":
	default:
		f.State = ""
	}
	if len(f.Query) > 100 {
		f.Query = f.Query[:100]
	}
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 0 || page > 100000 {
		page = 0
	}
	rows, total, err := s.Meta.ListUsersAdmin(r.Context(), f, page*adminPageSize, adminPageSize)
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	v := adminUsersView{Tabs: adminTabs(wv.web.link, "users"), Total: total, Q: f.Query, State: f.State, Tier: f.Tier,
		Sort: f.Sort, Desc: f.Desc, AdminOnly: f.AdminOnly, Page: page + 1, Pages: (total + adminPageSize - 1) / adminPageSize}
	for _, r2 := range rows {
		ur := userRow{AdminUserRow: r2, Name: r2.Username}
		if ur.Name == "" {
			ur.Name = r2.User.Subject
		}
		if r2.LastActive != nil {
			ur.Last = r2.LastActive.UTC().Format("2006-01-02")
		}
		if r2.QuotaBytes > 0 {
			ur.QuotaText = fmtBytes(float64(r2.QuotaBytes))
			ur.UsedPct = int(r2.UsedBytes * 100 / r2.QuotaBytes)
		}
		v.Rows = append(v.Rows, ur)
	}
	link := func(p int) string {
		u := url.Values{}
		for _, k := range []string{"q", "state", "tier", "sort", "dir", "admins"} {
			if x := q.Get(k); x != "" {
				u.Set(k, x)
			}
		}
		u.Set("page", strconv.Itoa(p))
		return wv.web.link + "admin/users?" + u.Encode()
	}
	if page > 0 {
		v.PrevHref = link(page - 1)
	}
	if (page+1)*adminPageSize < total {
		v.NextHref = link(page + 1)
	}
	for _, st := range [][2]string{{"", "All accounts"}, {"active", "Active"}, {"pending", "Waiting for approval"}, {"banned", "Banned"}, {"disabled", "Disabled"}, {"deleted", "Deleted"}} {
		v.States = append(v.States, stateOption{st[0], st[1], st[0] == f.State})
	}
	wv.render("admin_users", 200, v)
}

type adminUserView struct {
	Tabs         []adminTab
	U            meta.User
	Name         string
	Usage        meta.Usage
	UsedPct      int
	QuotaText    string
	Cred         *meta.WebCredential
	Status       *meta.UserStatus
	Locked       bool
	Tokens       []tokenRow
	Sessions     []meta.WebSession
	Audit        []meta.AuditEvent
	Notice       string
	Error        string
	TempPassword string
	Self         bool
}

func (s *Server) renderAdminUser(wv *webReq, notice, errMsg, temp string) {
	r := wv.r
	u, usage, err := s.Svc.AdminGetUser(r.Context(), wv.principal(), r.PathValue("id"))
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	v := adminUserView{Tabs: adminTabs(wv.web.link, "users"), U: u, Usage: usage, Name: u.Subject,
		Notice: notice, Error: errMsg, TempPassword: temp, Self: u.ID == wv.sess.UserID}
	if c, err := s.Meta.GetCredential(r.Context(), u.ID); err == nil {
		cc := c
		v.Cred = &cc
		v.Name = c.Username
		_, v.Locked = s.web.userLock.Locked()[c.Username]
	}
	if st, err := s.Meta.GetUserStatus(r.Context(), u.ID); err == nil {
		v.Status = &st
	}
	if usage.QuotaBytes > 0 {
		v.QuotaText = fmtBytes(float64(usage.QuotaBytes))
		v.UsedPct = int(usage.UsedBytes * 100 / usage.QuotaBytes)
	}
	v.Tokens = s.adminUserTokens(wv, u.ID)
	v.Sessions, _ = s.Meta.ListWebSessions(r.Context(), u.ID)
	v.Audit, _, _ = s.Meta.ListAudit(r.Context(), meta.AuditFilter{TargetID: u.ID}, "", 15)
	wv.render("admin_user", 200, v)
}
