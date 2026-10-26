// SPDX-License-Identifier: 0BSD

package server

import (
	"encoding/csv"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// expiryPresets are the lifetimes the token forms offer.
var expiryPresets = []struct {
	Value, Label string
	Dur          time.Duration
}{
	{"1d", "1 day", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
	{"90d", "90 days", 90 * 24 * time.Hour},
	{"180d", "180 days", 180 * 24 * time.Hour},
	{"1y", "1 year", 365 * 24 * time.Hour},
}

type expiryOption struct {
	Value, Label string
	Selected     bool
}

// tokenForm carries submitted values back into the forms.
type tokenForm struct {
	Name                string
	Read, Write, Admin  bool
	Apps                string
	Expires, Custom     string
	CIDRs               string
	Keep                bool
	DefaultNeverAllowed bool
}

func (s *Server) expiryOptions(selected string, withKeep bool) []expiryOption {
	max := s.Cfg.Auth.Token.MaxTTL.Duration()
	var out []expiryOption
	if withKeep {
		out = append(out, expiryOption{"keep", "Keep current", selected == "keep"})
	}
	for _, p := range expiryPresets {
		if max > 0 && p.Dur > max {
			continue
		}
		out = append(out, expiryOption{p.Value, p.Label, selected == p.Value})
	}
	if max == 0 {
		out = append(out, expiryOption{"never", "Never", selected == "never"})
	}
	return out
}

// defaultExpiry maps default_ttl onto the nearest preset not above max_ttl.
func (s *Server) defaultExpiry() string {
	d := s.Cfg.Auth.Token.DefaultTTL.Duration()
	max := s.Cfg.Auth.Token.MaxTTL.Duration()
	best := ""
	for _, p := range expiryPresets {
		if max > 0 && p.Dur > max {
			continue
		}
		if best == "" || (d > 0 && p.Dur <= d) {
			best = p.Value
		}
		if d > 0 && p.Dur >= d {
			break
		}
	}
	if best == "" {
		return "never"
	}
	if d == 0 && max == 0 {
		return "90d"
	}
	return best
}

func (s *Server) tokenLimitNote() string {
	if m := s.Cfg.Auth.Token.MaxTTL.Duration(); m > 0 {
		return "Tokens on this server must expire within " + durWords(m) + "."
	}
	return ""
}

func durWords(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 365 && days%365 == 0:
		if days == 365 {
			return "1 year"
		}
		return strconv.Itoa(days/365) + " years"
	case days >= 1:
		if days == 1 {
			return "1 day"
		}
		return strconv.Itoa(days) + " days"
	}
	return d.Round(time.Minute).String()
}

// tokenRow is one line of a token table.
type tokenRow struct {
	meta.Token
	Status   string
	Addrs    string
	ExpiresN string
}

func (s *Server) tokenRows(in []meta.Token) []tokenRow {
	now := s.Clock()
	out := make([]tokenRow, len(in))
	for i, t := range in {
		r := tokenRow{Token: t, Status: tokenState(t, now)}
		switch n := len(t.AllowedCIDRs); {
		case n == 0:
			r.Addrs = "Any address"
		case n == 1:
			r.Addrs = t.AllowedCIDRs[0]
		default:
			r.Addrs = t.AllowedCIDRs[0] + " and " + strconv.Itoa(n-1) + " more"
		}
		r.ExpiresN = relExpiry(t.ExpiresAt, now)
		out[i] = r
	}
	return out
}

func tokenState(t meta.Token, now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "Revoked"
	case t.ExpiresAt != nil && !t.ExpiresAt.After(now):
		return "Expired"
	}
	return "Active"
}

// relExpiry words an expiry relative to now.
func relExpiry(t *time.Time, now time.Time) string {
	if t == nil {
		return "Never expires"
	}
	d := t.Sub(now)
	past := d < 0
	if past {
		d = -d
	}
	var n string
	switch {
	case d < time.Hour:
		m := int(d.Minutes())
		if m < 1 {
			return map[bool]string{true: "just now", false: "in under a minute"}[past]
		}
		n = plural(m, "minute")
	case d < 48*time.Hour:
		n = plural(int(d.Hours()), "hour")
	default:
		n = plural(int(d.Hours()/24), "day")
	}
	if past {
		return "Expired " + n + " ago"
	}
	return "In " + n
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

func (s *Server) whTokens(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	notice := ""
	if r.URL.Query().Get("revoked") == "1" {
		notice = "Token revoked. It no longer authenticates."
	}
	s.renderTokens(wv, notice, "", "", tokenForm{Read: true, Expires: s.defaultExpiry()})
}

func (s *Server) renderTokens(wv *webReq, notice, errMsg, newToken string, f tokenForm) {
	toks, err := s.Svc.ListTokens(wv.r.Context(), wv.principal(), wv.sess.UserID)
	if err != nil {
		s.webServiceError(wv, err)
		return
	}
	slices.Reverse(toks)
	wv.render("tokens", 200, struct {
		Tokens       []tokenRow
		NewToken     string
		AdminAllowed bool
		Notice       string
		Error        string
		ClientIP     string
		Form         tokenForm
		Options      []expiryOption
		LimitNote    string
	}{Tokens: s.tokenRows(toks), NewToken: newToken, AdminAllowed: wv.sess.Admin, Notice: notice,
		Error: errMsg, ClientIP: s.clientAddr(wv.r), Form: f,
		Options: s.expiryOptions(f.Expires, false), LimitNote: s.tokenLimitNote()})
}

// readTokenForm captures the create form values.
func readTokenForm(r *http.Request) tokenForm {
	return tokenForm{
		Name: strings.TrimSpace(r.PostForm.Get("name")),
		Read: r.PostForm.Get("scope_read") == "1", Write: r.PostForm.Get("scope_write") == "1",
		Admin:   r.PostForm.Get("scope_admin") == "1",
		Apps:    r.PostForm.Get("apps"),
		Expires: r.PostForm.Get("expires"), Custom: strings.TrimSpace(r.PostForm.Get("expires_custom")),
		CIDRs: r.PostForm.Get("allowed_cidrs"),
	}
}

func (s *Server) whTokenCreate(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	f := readTokenForm(r)
	fail := func(msg string) { s.renderTokens(wv, "", msg, "", f) }
	if f.Name == "" || len(f.Name) > 128 {
		fail("A token name is required (max 128 characters).")
		return
	}
	var scopes []string
	if f.Read {
		scopes = append(scopes, "read")
	}
	if f.Write {
		scopes = append(scopes, "write")
	}
	if wv.sess.Admin && f.Admin {
		scopes = append(scopes, "admin")
	}
	if len(scopes) == 0 {
		fail("Choose at least one scope.")
		return
	}
	var apps []string
	for _, a := range strings.Split(f.Apps, ",") {
		if a = strings.TrimSpace(a); a != "" {
			apps = append(apps, a)
		}
	}
	exp, err := s.webExpiry(f.Expires, f.Custom, false)
	if err != nil {
		fail(err.Error())
		return
	}
	cidrs, err := auth.ValidateCIDRs(f.CIDRs)
	if err != nil {
		fail("Allowed addresses: " + err.Error())
		return
	}
	out, err := s.Svc.CreateToken(r.Context(), wv.principal(), wv.sess.UserID, f.Name, scopes, apps, exp, cidrs)
	if err != nil {
		if msg := problemMessage(err); msg != "" {
			fail(msg)
			return
		}
		s.webServiceError(wv, err)
		return
	}
	// The secret is rendered once, never redirected or stored.
	s.renderTokens(wv, "", "", out.Full, tokenForm{Read: true, Expires: s.defaultExpiry()})
}

// problemMessage returns the fixed title of a 4xx service problem.
func problemMessage(err error) string {
	var p *api.Problem
	if errors.As(err, &p) && p.Status >= 400 && p.Status < 500 && p.Status != 403 && p.Status != 404 {
		return p.Title
	}
	return ""
}

// webExpiry resolves a preset or a custom UTC time. With keep true
// the value "keep" is understood by the caller and not handled here.
// A nil time means no expiry.
func (s *Server) webExpiry(preset, custom string, _ bool) (*time.Time, error) {
	now := s.Clock().UTC()
	if custom != "" {
		for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", time.RFC3339} {
			if t, err := time.Parse(layout, custom); err == nil {
				t = t.UTC()
				if !t.After(now) {
					return nil, userError("The expiry must be in the future.")
				}
				if t.After(now.Add(10 * 365 * 24 * time.Hour)) {
					return nil, userError("The expiry must be within ten years.")
				}
				return &t, nil
			}
		}
		return nil, userError("Custom expiry must be a UTC date and time such as 2027-01-31T09:30.")
	}
	if preset == "never" {
		return nil, nil
	}
	for _, p := range expiryPresets {
		if p.Value == preset {
			t := now.Add(p.Dur)
			return &t, nil
		}
	}
	if preset == "" {
		if d := s.Cfg.Auth.Token.DefaultTTL.Duration(); d > 0 {
			t := now.Add(d)
			return &t, nil
		}
		t := now.Add(90 * 24 * time.Hour)
		return &t, nil
	}
	return nil, userError("Choose an expiry from the list.")
}

func (s *Server) whTokenRevokeGet(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	id := r.PathValue("id")
	t, err := s.Svc.GetToken(r.Context(), wv.principal(), id)
	if err != nil {
		s.tokenError(wv, err)
		return
	}
	wv.render("confirm", 200, struct {
		Heading, Warning, URL, Back string
	}{
		Heading: "Revoke token",
		Warning: "The token " + t.Name + " will stop working immediately. This cannot be undone.",
		URL:     wv.web.link + "account/tokens/" + url.PathEscape(id) + "/revoke",
		Back:    wv.web.link + "account/tokens/" + url.PathEscape(id),
	})
}

func (s *Server) whTokenRevoke(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	id := r.PathValue("id")
	if err := s.Svc.RevokeToken(r.Context(), wv.principal(), id); err != nil {
		s.tokenError(wv, err)
		return
	}
	http.Redirect(w, r, wv.web.link+"account/tokens?revoked=1", http.StatusSeeOther) // #nosec G710 -- fixed route under the link prefix
}

// tokenError hides the existence of other users' tokens behind 404.
func (s *Server) tokenError(wv *webReq, err error) {
	var p *api.Problem
	if errors.Is(err, auth.ErrForbidden) || (errors.As(err, &p) && p.Status == 403) {
		wv.errorPage(404)
		return
	}
	s.webServiceError(wv, err)
}

type chartBar struct {
	X, Y, W, H int
	Day        string
	Count      int64
}

type tokenDetail struct {
	Token     tokenRow
	Owner     string
	Foreign   bool
	Stats     meta.TokenStats
	Bars      []chartBar
	ChartMax  int64
	Events    []meta.TokenEvent
	Next      string
	Kind      string
	Kinds     []kindOption
	Form      tokenForm
	Options   []expiryOption
	LimitNote string
	Notice    string
	Error     string
	ClientIP  string
	Revoked   bool
}

type kindOption struct{ Value, Label string }

var kindLabels = []kindOption{
	{"created", "Created"}, {"first_use", "First use"}, {"new_ip", "New address"},
	{"denied_ip", "Blocked address"}, {"denied_expired", "Blocked, expired"}, {"denied_revoked", "Blocked, revoked"},
	{"expiry_changed", "Expiry changed"}, {"cidr_changed", "Addresses changed"},
	{"renamed", "Renamed"}, {"revoked", "Revoked"},
}

func (s *Server) whTokenDetail(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	s.renderTokenDetail(wv, "", "", nil)
}

func (s *Server) renderTokenDetail(wv *webReq, notice, errMsg string, form *tokenForm) {
	r := wv.r
	id := r.PathValue("id")
	p := wv.principal()
	t, err := s.Svc.GetToken(r.Context(), p, id)
	if err != nil {
		s.tokenError(wv, err)
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind != "" && !validEventKind(kind) {
		kind = ""
	}
	cursor := r.URL.Query().Get("cursor")
	ev, next, err := s.Svc.TokenEvents(r.Context(), p, id, kind, cursor, 50)
	if err != nil {
		if _, _, derr := meta.DecodeCursor(cursor); derr != nil {
			wv.errorPage(400)
			return
		}
		s.tokenError(wv, err)
		return
	}
	st, err := s.Svc.TokenStats(r.Context(), p, id)
	if err != nil {
		s.tokenError(wv, err)
		return
	}
	d := tokenDetail{Token: s.tokenRows([]meta.Token{t})[0], Stats: st, Events: ev, Next: next, Kind: kind,
		Kinds: kindLabels, LimitNote: s.tokenLimitNote(), Notice: notice, Error: errMsg,
		ClientIP: s.clientAddr(r), Revoked: t.RevokedAt != nil, Foreign: t.UserID != wv.sess.UserID}
	if d.Foreign {
		if u, err := s.Meta.GetUser(r.Context(), t.UserID); err == nil {
			d.Owner = u.Subject
		}
		if c, err := s.Meta.GetCredential(r.Context(), t.UserID); err == nil {
			d.Owner = c.Username
		}
	}
	d.Bars, d.ChartMax = chartBars(st.Daily, s.Clock())
	if form != nil {
		d.Form = *form
	} else {
		d.Form = tokenForm{Name: t.Name, Expires: "keep", CIDRs: strings.Join(t.AllowedCIDRs, "\n")}
	}
	d.Options = s.expiryOptions(d.Form.Expires, true)
	wv.render("token", 200, d)
}

// chartBars lays out the 30 day series as SVG rect geometry.
func chartBars(daily []int64, now time.Time) ([]chartBar, int64) {
	const w, h, gap = 8, 60, 2
	var max int64
	for _, c := range daily {
		if c > max {
			max = c
		}
	}
	out := make([]chartBar, len(daily))
	start := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -(len(daily) - 1))
	for i, c := range daily {
		bh := 1
		if max > 0 && c > 0 {
			bh = int(float64(h) * float64(c) / float64(max))
			if bh < 2 {
				bh = 2
			}
		}
		out[i] = chartBar{X: i * (w + gap), Y: h - bh, W: w, H: bh, Count: c,
			Day: start.AddDate(0, 0, i).Format("2006-01-02")}
	}
	return out, max
}

func (s *Server) whTokenEdit(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	id := r.PathValue("id")
	p := wv.principal()
	cur, err := s.Svc.GetToken(r.Context(), p, id)
	if err != nil {
		s.tokenError(wv, err)
		return
	}
	f := tokenForm{Name: strings.TrimSpace(r.PostForm.Get("name")), Expires: r.PostForm.Get("expires"),
		Custom: strings.TrimSpace(r.PostForm.Get("expires_custom")), CIDRs: r.PostForm.Get("allowed_cidrs")}
	if f.Expires == "" {
		f.Expires = "keep"
	}
	fail := func(msg string) { s.renderTokenDetail(wv, "", msg, &f) }
	var patch meta.TokenPatch
	if f.Name != cur.Name {
		if f.Name == "" || len(f.Name) > 128 {
			fail("A token name is required (max 128 characters).")
			return
		}
		patch.Name = &f.Name
	}
	if f.Custom != "" || f.Expires != "keep" {
		exp, err := s.webExpiry(f.Expires, f.Custom, true)
		if err != nil {
			fail(err.Error())
			return
		}
		patch.ExpiresAt = &exp
	}
	cidrs, err := auth.ValidateCIDRs(f.CIDRs)
	if err != nil {
		fail("Allowed addresses: " + err.Error())
		return
	}
	if !slices.Equal(cidrs, cur.AllowedCIDRs) && !(len(cidrs) == 0 && len(cur.AllowedCIDRs) == 0) {
		patch.CIDRs = &cidrs
	}
	if patch.Name == nil && patch.ExpiresAt == nil && patch.CIDRs == nil {
		s.renderTokenDetail(wv, "Nothing changed.", "", nil)
		return
	}
	if err := s.Svc.UpdateToken(r.Context(), p, id, patch); err != nil {
		if msg := problemMessage(err); msg != "" {
			fail(msg)
			return
		}
		s.tokenError(wv, err)
		return
	}
	s.Log.Info("web token updated", "user", wv.sess.UserID, "token", id)
	s.renderTokenDetail(wv, "Token updated.", "", nil)
}

// csvCell neutralizes spreadsheet formula injection.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) whTokenAuditCSV(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	id := r.PathValue("id")
	p := wv.principal()
	if _, err := s.Svc.GetToken(r.Context(), p, id); err != nil {
		s.tokenError(wv, err)
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind != "" && !validEventKind(kind) {
		kind = ""
	}
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="token-`+url.PathEscape(id)+`-audit.csv"`)
	h.Set("Cache-Control", "no-store")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "event", "address", "actor", "user_agent", "detail"})
	cursor := ""
	for n := 0; n < 10; n++ {
		ev, next, err := s.Svc.TokenEvents(r.Context(), p, id, kind, cursor, 500)
		if err != nil {
			s.Log.Warn("token audit csv", "err", err)
			break
		}
		for _, e := range ev {
			_ = cw.Write([]string{e.At.UTC().Format(time.RFC3339), e.Kind, csvCell(e.IP),
				csvCell(e.ActorID), csvCell(e.UserAgent), csvCell(e.Detail)})
		}
		if next == "" {
			break
		}
		cursor = next
	}
	cw.Flush()
}

func (s *Server) adminUserTokens(wv *webReq, userID string) []tokenRow {
	toks, err := s.Svc.ListTokens(wv.r.Context(), wv.principal(), userID)
	if err != nil {
		return nil
	}
	slices.Reverse(toks)
	return s.tokenRows(toks)
}

// clientAddr is the caller's plain address for display.
func (s *Server) clientAddr(r *http.Request) string {
	return netx.ClientIPReal(r, s.trustedCIDRs(), s.Cfg.Proxy.RealIPHeader).String()
}

// userError is a message written for the person using the form.
type userError string

func (e userError) Error() string { return string(e) }
