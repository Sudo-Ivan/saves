// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/ratelimit"
	"github.com/Sudo-Ivan/saves/internal/server/webui"
)

// webUI bundles everything the browser interface needs.
type webUI struct {
	tmpl         map[string]*template.Template
	pub          *url.URL
	base         string // cookie Path: "/" or the public_url prefix without trailing slash
	link         string // link prefix, always ends in "/"
	csrfKey      []byte
	loginLimiter *ratelimit.Limiter
	userLock     *usernameLock
	mux          *http.ServeMux
	any          *http.ServeMux
	allow        map[string][]string
	routeList    []webRoute
}

// webRoute records a registered route for tests.
type webRoute struct {
	Method  string
	Pattern string
}

// newWebUI builds the web layer; template parse errors are fatal.
func (s *Server) newWebUI() *webUI {
	base := "/"
	var pub *url.URL
	if p := s.Cfg.Web.PublicURL; p != "" {
		u, err := url.Parse(p)
		if err != nil {
			panic("web: bad public_url: " + err.Error())
		}
		pub = u
		base = u.EscapedPath()
		if base == "" {
			base = "/"
		}
		base = strings.TrimSuffix(base, "/")
		if base == "" {
			base = "/"
		}
	}
	key, err := auth.DeriveKey([]byte(s.Cfg.Web.Secret), auth.SealCSRFHMAC)
	if err != nil {
		panic("web: " + err.Error())
	}
	link := base
	if link != "/" {
		link += "/"
	}
	w := &webUI{
		pub:     pub,
		base:    base,
		link:    link,
		csrfKey: key,
		loginLimiter: ratelimit.New(s.Cfg.Web.LoginPerMin/60,
			s.Cfg.Web.LoginPerMin, 1<<16, s.Clock),
		userLock: newUsernameLock(s.Clock),
		mux:      http.NewServeMux(),
		any:      http.NewServeMux(),
		allow:    map[string][]string{},
	}
	fm := webui.Funcs(link)
	fm["md"] = docMarkdown
	fm["lower"] = strings.ToLower
	fm["tagid"] = func(s string) string { return strings.ReplaceAll(strings.ToLower(s), " ", "-") }
	w.tmpl, err = webui.Parse(fm)
	if err != nil {
		panic("web: " + err.Error())
	}
	w.routes(s)
	return w
}

// route registers one web route on both muxes.
func (w *webUI) route(method, pattern string, h http.HandlerFunc) {
	w.mux.HandleFunc(method+" "+pattern, h)
	if _, seen := w.allow[pattern]; !seen {
		w.any.HandleFunc(pattern, func(rw http.ResponseWriter, r *http.Request) {})
	}
	w.allow[pattern] = append(w.allow[pattern], method)
	w.routeList = append(w.routeList, webRoute{Method: method, Pattern: pattern})
}

func (w *webUI) routes(s *Server) {
	w.route("GET", "/", s.whHome)
	w.route("GET", "/login", s.whLoginGet)
	w.route("POST", "/login", s.whLoginPost)
	w.route("GET", "/login/2fa", s.wh2faGet)
	w.route("POST", "/login/2fa", s.wh2faPost)
	w.route("GET", "/register", s.whRegisterGet)
	w.route("POST", "/register", s.whRegisterPost)
	w.route("GET", "/auth/oidc/start", s.whOIDCStart)
	w.route("GET", "/auth/oidc/callback", s.whOIDCCallback)
	w.route("GET", "/static/{name...}", s.whStatic)
	w.route("GET", "/robots.txt", s.whRobots)
	w.route("GET", "/docs", s.whDocs)
	w.route("GET", "/openapi.yaml", s.whSpec)
	w.route("POST", "/logout", s.whLogout)

	w.route("GET", "/account", s.whAccount)
	w.route("GET", "/account/apps/{app}", s.whApp)
	w.route("GET", "/account/apps/{app}/slots/{slot}", s.whSlot)
	w.route("GET", "/account/apps/{app}/slots/{slot}/snapshots/{id}", s.whSnapshot)
	w.route("GET", "/account/apps/{app}/slots/{slot}/snapshots/{id}/view/{path...}", s.whFileView)
	w.route("GET", "/account/apps/{app}/slots/{slot}/snapshots/{id}/raw/{path...}", s.whFileRaw)
	w.route("GET", "/account/apps/{app}/slots/{slot}/snapshots/{id}/diff/{other}", s.whDiff)
	w.route("GET", "/account/apps/{app}/slots/{slot}/snapshots/{id}/archive.tar", s.whArchive)
	w.route("GET", "/account/apps/{app}/slots/{slot}/snapshots/{id}/delete", s.whSnapshotDeleteGet)
	w.route("POST", "/account/apps/{app}/slots/{slot}/snapshots/{id}/delete", s.whSnapshotDeletePost)
	w.route("GET", "/account/apps/{app}/slots/{slot}/delete", s.whSlotDeleteGet)
	w.route("POST", "/account/apps/{app}/slots/{slot}/delete", s.whSlotDeletePost)
	w.route("GET", "/account/security", s.whSecurity)
	w.route("POST", "/account/security/password", s.whPasswordChange)
	w.route("GET", "/account/security/2fa", s.wh2faSetupGet)
	w.route("POST", "/account/security/2fa", s.wh2faSetupPost)
	w.route("POST", "/account/security/2fa/disable", s.wh2faDisable)
	w.route("POST", "/account/security/recovery", s.whRecoveryRegen)
	w.route("POST", "/account/security/sessions/{hash}/revoke", s.whSessionRevoke)
	w.route("POST", "/account/security/sessions/revoke-others", s.whSessionRevokeOthers)
	w.route("GET", "/account/tokens", s.whTokens)
	w.route("POST", "/account/tokens", s.whTokenCreate)
	w.route("GET", "/account/tokens/{id}", s.whTokenDetail)
	w.route("POST", "/account/tokens/{id}/edit", s.whTokenEdit)
	w.route("GET", "/account/tokens/{id}/revoke", s.whTokenRevokeGet)
	w.route("POST", "/account/tokens/{id}/revoke", s.whTokenRevoke)
	w.route("GET", "/account/tokens/{id}/audit.csv", s.whTokenAuditCSV)

	w.route("GET", "/admin", s.whAdmin)
	w.route("GET", "/admin/system", s.whAdminSystem)
	w.route("GET", "/admin/security", s.whAdminSecurity)
	w.route("GET", "/admin/access", s.whAdminAccess)
	w.route("POST", "/admin/invites", s.whAdminInviteCreate)
	w.route("POST", "/admin/invites/{id}/revoke", s.whAdminInviteRevoke)
	w.route("POST", "/admin/ip-blocks", s.whAdminBlockCreate)
	w.route("POST", "/admin/ip-blocks/{id}/remove", s.whAdminBlockDelete)
	w.route("GET", "/admin/settings", s.whAdminSettings)
	w.route("POST", "/admin/settings", s.whAdminSettingsSave)
	w.route("POST", "/admin/settings/reset", s.whAdminSettingsReset)
	w.route("GET", "/admin/audit", s.whAdminAudit)
	w.route("GET", "/admin/audit.csv", s.whAdminAuditCSV)
	w.route("POST", "/admin/fsck", s.whAdminFsck)
	w.route("POST", "/admin/backup", s.whAdminBackup)
	w.route("GET", "/admin/users", s.whAdminUsers)
	w.route("GET", "/admin/users/{id}", s.whAdminUser)
	w.route("GET", "/admin/users/{id}/delete", s.whAdminUserDeleteGet)
	w.route("POST", "/admin/users/{id}", s.whAdminUserPost)
	w.route("POST", "/admin/gc", s.whAdminGC)
}

// webCtxKey carries the per-request web state.
type webCtxKey struct{}

// webFrom returns the request-scoped web state; every handler uses it.
func webFrom(r *http.Request) *webReq {
	return r.Context().Value(webCtxKey{}).(*webReq)
}

// webServe handles a non-API request.
func (s *Server) webServe(w http.ResponseWriter, r *http.Request) {
	web := s.web
	wv := &webReq{s: s, w: w, r: r, web: web, path: r.URL.Path}
	wv.secure = web.secureFor(s, r)
	wv.host = web.hostFor(s, r)

	// Public URL host enforcement: compare the incoming Host (after
	// trusted rewriting), not the configured one.
	if web.pub != nil && !hostMatch(web.incomingHost(s, r), web.pub.Host) {
		wv.errorPage(421)
		return
	}
	// Strip the configured path prefix; also accept requests where the
	// proxy already stripped it.
	stripped := wv.path != r.URL.Path
	if web.base != "/" {
		if wv.path == web.base {
			wv.path = "/"
			stripped = true
		} else if strings.HasPrefix(wv.path, web.base+"/") {
			wv.path = strings.TrimPrefix(wv.path, web.base)
			stripped = true
		}
	}
	wv.headers()

	if r.Method == http.MethodOptions {
		wv.errorPage(405)
		return
	}

	r2 := r.Clone(r.Context())
	if stripped {
		u := *r.URL
		u.Path = wv.path
		u.RawPath = ""
		r2.URL = &u
	}
	r2 = r2.WithContext(context.WithValue(r2.Context(), webCtxKey{}, wv))
	wv.r = r2

	_, pat := web.mux.Handler(r2)
	if pat == "" {
		_, apat := web.any.Handler(r2)
		if apat != "" {
			w.Header().Set("Allow", strings.Join(web.allow[apat], ", "))
			wv.errorPage(405)
			return
		}
		wv.errorPage(404)
		return
	}
	// ServeHTTP re-dispatches so PathValue is populated on r2.
	web.mux.ServeHTTP(w, r2)
}

// hostMatch compares host names case-insensitively, tolerating
// explicit ports on either side.
func hostMatch(got, want string) bool {
	if strings.EqualFold(got, want) {
		return true
	}
	gh, _, gerr := net.SplitHostPort(got)
	if gerr != nil {
		gh = got
	}
	wh, _, werr := net.SplitHostPort(want)
	if werr != nil {
		wh = want
	}
	return strings.EqualFold(gh, wh)
}

// usernameLock is a bounded per-username failure counter that locks a
// username for 15 minutes after 10 failures inside 15 minutes.
type usernameLock struct {
	mu    sync.Mutex
	clock func() time.Time
	m     map[string]*lockEnt
}

type lockEnt struct {
	fails  int
	window time.Time
	until  time.Time
}

const (
	lockWindow   = 15 * time.Minute
	lockMaxFails = 10
	lockMaxKeys  = 4096
)

func newUsernameLock(clock func() time.Time) *usernameLock {
	return &usernameLock{clock: clock, m: map[string]*lockEnt{}}
}

// locked reports whether the username is currently locked out.
func (l *usernameLock) locked(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[name]
	return ok && l.clock().Before(e.until)
}

// SetLoginLimit rebuilds the per-IP login limiter on settings change.
func (s *Server) SetLoginLimit(perMin float64) {
	if s.web != nil {
		s.web.loginLimiter = ratelimit.New(perMin/60, perMin, 1<<16, s.Clock)
	}
}

// Locked lists usernames currently locked with their unlock time.
func (l *usernameLock) Locked() map[string]time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]time.Time{}
	for k, e := range l.m {
		if l.clock().Before(e.until) {
			out[k] = e.until
		}
	}
	return out
}

// ClearUnlock removes one or all lockouts.
func (l *usernameLock) ClearUnlock(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if name == "" {
		l.m = map[string]*lockEnt{}
		return
	}
	delete(l.m, name)
}

// fail records one failed attempt for the username.
func (l *usernameLock) fail(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	e, ok := l.m[name]
	if !ok {
		if len(l.m) >= lockMaxKeys {
			for k := range l.m { // drop an arbitrary entry, keep bounded
				delete(l.m, k)
				break
			}
		}
		e = &lockEnt{window: now}
		l.m[name] = e
	}
	if now.Sub(e.window) > lockWindow {
		e.fails = 0
		e.window = now
	}
	e.fails++
	if e.fails >= lockMaxFails {
		e.until = now.Add(lockWindow)
		e.fails = 0
		e.window = now
	}
}

// reset clears the failure counter after a success.
func (l *usernameLock) reset(name string) {
	l.mu.Lock()
	delete(l.m, name)
	l.mu.Unlock()
}

// trustedPeer reports whether the direct peer may set forwarding
// headers.
func (s *Server) trustedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, p := range s.trustedCIDRs() {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// forwardedProto reads X-Forwarded-Proto or the Forwarded proto
// parameter. Callers must only consult it for trusted peers.
func forwardedProto(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(v, ",")[0]))
	}
	for _, fwd := range r.Header.Values("Forwarded") {
		for _, part := range strings.Split(fwd, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 && strings.EqualFold(kv[0], "proto") {
				return strings.ToLower(strings.Trim(kv[1], `"`))
			}
		}
	}
	return ""
}

// secureFor computes the effective Secure flag for cookies.
func (w *webUI) secureFor(s *Server, r *http.Request) bool {
	switch s.Cfg.Web.CookieSecure {
	case "always":
		return true
	case "never":
		return false
	}
	if w.pub != nil {
		return w.pub.Scheme == "https"
	}
	if r.TLS != nil {
		return true
	}
	return s.trustedPeer(r) && forwardedProto(r) == "https"
}

// schemeFor computes the effective request scheme.
func (w *webUI) schemeFor(s *Server, r *http.Request) string {
	if w.pub != nil {
		return w.pub.Scheme
	}
	if r.TLS != nil {
		return "https"
	}
	if s.trustedPeer(r) {
		if p := forwardedProto(r); p == "https" || p == "http" {
			return p
		}
	}
	return "http"
}

// incomingHost returns the Host header honoring trusted proxy
// rewriting, ignoring public_url.
func (w *webUI) incomingHost(s *Server, r *http.Request) string {
	if s.trustedPeer(r) {
		if h := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); h != "" {
			return h
		}
	}
	return r.Host
}

// hostFor computes the effective request host.
func (w *webUI) hostFor(s *Server, r *http.Request) string {
	if w.pub != nil {
		return w.pub.Host
	}
	if s.trustedPeer(r) {
		if h := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); h != "" {
			return h
		}
	}
	return r.Host
}

// webReq is per-request web state.
type webReq struct {
	s      *Server
	w      http.ResponseWriter
	r      *http.Request
	web    *webUI
	path   string // prefix-stripped path
	host   string
	secure bool
	origin string

	sess     *meta.WebSession
	user     *meta.User
	cred     *meta.WebCredential
	sessDone bool
	sessID   string // raw cookie value, for same-request use
	csrfVal  string // unauthenticated csrf cookie value
	csrfNew  bool
}

// headers sets the full web security header set.
func (wv *webReq) headers() {
	h := wv.w.Header()
	scheme := wv.web.schemeFor(wv.s, wv.r)
	csp := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; " +
		"base-uri 'none'; object-src 'none'; manifest-src 'self'"
	if scheme == "https" {
		csp += "; upgrade-insecure-requests"
	}
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()")
	h.Set("X-Robots-Tag", "noindex")
	if c := wv.s.Cfg.Web.HSTS; c.Enabled && scheme == "https" {
		v := "max-age=" + strconv.FormatInt(int64(c.MaxAge.Duration().Seconds()), 10)
		if c.IncludeSubdomains {
			v += "; includeSubDomains"
		}
		if c.Preload {
			v += "; preload"
		}
		h.Set("Strict-Transport-Security", v)
	}
}

// cookieName applies the __Host- or __Secure- prefix rules.
func (wv *webReq) cookieName(base string) string {
	if wv.secure && wv.web.base == "/" {
		return "__Host-" + base
	}
	if wv.secure {
		return "__Secure-" + base
	}
	return base
}

func (wv *webReq) cookiePath() string { return wv.web.base }

// setCookie writes a cookie under the web rules.
func (wv *webReq) setCookie(name, value string, maxAge int, strict bool) {
	s := http.SameSiteLaxMode
	if strict {
		s = http.SameSiteStrictMode
	}
	http.SetCookie(wv.w, &http.Cookie{ // #nosec G124 -- attributes come from the effective scheme rules in cookieName and setCookie
		Name: wv.cookieName(name), Value: value, Path: wv.cookiePath(),
		HttpOnly: true, Secure: wv.secure, SameSite: s, MaxAge: maxAge,
	})
}

func (wv *webReq) readCookie(base string) string {
	c, err := wv.r.Cookie(wv.cookieName(base))
	if err != nil {
		return ""
	}
	return c.Value
}

const (
	sessCookie = "sess"
	csrfCookie = "csrf"
	oidcCookie = "oidc"
)

func newSessionID() (val string, hash [32]byte, err error) {
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return
	}
	val = base64.RawURLEncoding.EncodeToString(b[:])
	hash = sha256.Sum256([]byte(val))
	return
}

// createSession stores a session and sets the cookie.
func (wv *webReq) createSession(userID, kind, method string, admin bool, ttl time.Duration) error {
	val, hash, err := newSessionID()
	if err != nil {
		return err
	}
	var csrf [32]byte
	if _, err := rand.Read(csrf[:]); err != nil {
		return err
	}
	now := wv.s.Clock()
	ws := meta.WebSession{
		IDHash: hash, UserID: userID, Kind: kind, Method: method, Admin: admin,
		CSRF: csrf, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(ttl),
		IP: wv.s.clientIP(wv.r), UserAgent: uaClean(wv.r.Header.Get("User-Agent")),
	}
	if err := wv.s.Meta.CreateWebSession(wv.r.Context(), ws); err != nil {
		return err
	}
	wv.setCookie(sessCookie, val, 0, false)
	return nil
}

// uaClean strips control chars and truncates to 200 bytes.
func uaClean(ua string) string {
	ua = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, ua)
	if len(ua) > 200 {
		ua = ua[:200]
	}
	return ua
}

// loadSession resolves the session cookie. A missing, expired, or
// invalid session leaves wv.sess nil.
func (wv *webReq) loadSession() {
	if wv.sessDone {
		return
	}
	wv.sessDone = true
	val := wv.readCookie(sessCookie)
	if val == "" {
		return
	}
	wv.sessID = val
	hash := sha256.Sum256([]byte(val))
	ws, err := wv.s.Meta.GetWebSession(wv.r.Context(), hash)
	if err != nil {
		return
	}
	now := wv.s.Clock()
	cfg := wv.s.Cfg.Web.Session
	idle := cfg.Idle.Duration()
	if v := wv.s.siteVals(); v.SessionIdle > 0 {
		idle = v.SessionIdle.Duration()
	}
	if !now.Before(ws.ExpiresAt) || !now.Before(ws.LastSeenAt.Add(idle)) {
		_ = wv.s.Meta.DeleteWebSession(wv.r.Context(), hash)
		return
	}
	u, err := wv.s.Meta.GetUser(wv.r.Context(), ws.UserID)
	if err != nil || u.Disabled || u.DeletedAt != nil {
		_ = wv.s.Meta.DeleteWebSession(wv.r.Context(), hash)
		return
	}
	// Touch at most once a minute.
	if now.Sub(ws.LastSeenAt) >= time.Minute {
		_ = wv.s.Meta.TouchWebSession(wv.r.Context(), hash, now)
		ws.LastSeenAt = now
	}
	wv.sess = &ws
	wv.user = &u
	if c, err := wv.s.Meta.GetCredential(wv.r.Context(), ws.UserID); err == nil {
		wv.cred = &c
	}
}

// principal builds the API-equivalent principal for the session.
func (wv *webReq) principal() auth.Principal {
	sc := auth.ScopeRead | auth.ScopeWrite
	if wv.effectiveAdmin() {
		sc |= auth.ScopeAdmin
	}
	return auth.Principal{User: *wv.user, Scopes: sc, Admin: wv.effectiveAdmin()}
}

// requireAuth enforces a full session plus the must-change and forced
// 2FA rules. It writes the redirect or error itself.
func (wv *webReq) requireAuth() bool {
	wv.loadSession()
	if wv.sess == nil || wv.sess.Kind != meta.SessionFull {
		wv.redirectLogin()
		return false
	}
	if wv.cred != nil && wv.cred.MustChange {
		ok := wv.path == "/account/security" || (wv.path == "/account/security/password" && wv.r.Method == "POST")
		if !ok {
			http.Redirect(wv.w, wv.r, wv.web.link+"account/security", http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
			return false
		}
		return true // password change first; the 2FA gate applies after
	}
	cfg := wv.s.Cfg.Web
	if wv.sess.Method == meta.SessionMethodPassword &&
		(wv.cred == nil || !wv.cred.TOTPEnabled) &&
		(cfg.Require2FA || (wv.effectiveAdmin() && cfg.Require2FAAdmin)) &&
		wv.path != "/account/security/2fa" {
		http.Redirect(wv.w, wv.r, wv.web.link+"account/security/2fa", http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
		return false
	}
	return true
}

func (wv *webReq) redirectLogin() {
	http.Redirect(wv.w, wv.r, wv.web.link+"login?next="+url.QueryEscape(safeNext(wv.path)), http.StatusSeeOther) // #nosec G710 -- target is the link prefix plus a fixed, escaped or safeNext validated path
}

// effectiveAdmin derives the admin bit per request: password sessions
// require a current credential admin flag, OIDC keeps the login claim.
func (wv *webReq) effectiveAdmin() bool {
	if wv.sess.Method == meta.SessionMethodOIDC {
		return wv.sess.Admin
	}
	return wv.sess.Admin && wv.cred != nil && wv.cred.Admin
}

func (wv *webReq) requireAdmin() bool {
	if !wv.requireAuth() {
		return false
	}
	if !wv.effectiveAdmin() {
		wv.errorPage(403)
		return false
	}
	return true
}

// parseForm enforces the form content type and the 32 KiB body cap.
func (wv *webReq) parseForm() bool {
	if ct := wv.r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		wv.errorPage(400)
		return false
	}
	wv.r.Body = http.MaxBytesReader(wv.w, wv.r.Body, 32<<10)
	if err := wv.r.ParseForm(); err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			wv.errorPage(413)
		} else {
			wv.errorPage(400)
		}
		return false
	}
	return true
}

// checkFetchOrigin enforces the Fetch Metadata and Origin rules for
// state changing requests.
func (wv *webReq) checkFetchOrigin() bool {
	if sfs := wv.r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin" || sfs == "none"
	}
	origin := wv.originOf()
	if o := wv.r.Header.Get("Origin"); o != "" {
		return o == origin
	}
	if ref := wv.r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && u.Scheme+"://"+u.Host == origin
	}
	return false
}

func (wv *webReq) originOf() string {
	if wv.origin == "" {
		wv.origin = wv.web.schemeFor(wv.s, wv.r) + "://" + wv.host
	}
	return wv.origin
}

// requireCSRF runs both CSRF layers and writes the 403 on failure.
func (wv *webReq) requireCSRF() bool {
	if !wv.checkFetchOrigin() || !wv.checkCSRFToken() {
		wv.errorPage(403)
		return false
	}
	return true
}

// checkCSRFToken validates the csrf_token form field.
func (wv *webReq) checkCSRFToken() bool {
	tok := wv.r.PostForm.Get("csrf_token")
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != 64 {
		return false
	}
	var pad, masked [32]byte
	copy(pad[:], raw[:32])
	copy(masked[:], raw[32:])
	var secret [32]byte
	for i := range secret {
		secret[i] = pad[i] ^ masked[i]
	}
	if wv.sess != nil {
		return subtle.ConstantTimeCompare(secret[:], wv.sess.CSRF[:]) == 1
	}
	cookie := wv.readCookie(csrfCookie)
	if cookie == "" {
		return false
	}
	mac := auth.HMAC(wv.web.csrfKey, []byte(cookie))
	return subtle.ConstantTimeCompare(secret[:], mac[:]) == 1
}

// csrfToken mints a masked token for the current request context.
func (wv *webReq) csrfToken() string {
	wv.loadSession()
	var secret [32]byte
	if wv.sess != nil {
		secret = wv.sess.CSRF
	} else {
		secret = auth.HMAC(wv.web.csrfKey, []byte(wv.csrfCookieValue()))
	}
	var pad [32]byte
	_, _ = rand.Read(pad[:])
	tok := make([]byte, 64)
	copy(tok, pad[:])
	for i := range secret {
		tok[32+i] = pad[i] ^ secret[i]
	}
	return base64.RawURLEncoding.EncodeToString(tok)
}

// csrfCookieValue returns the unauthenticated CSRF cookie value,
// minting and setting one when absent.
func (wv *webReq) csrfCookieValue() string {
	if wv.csrfVal != "" {
		return wv.csrfVal
	}
	if v := wv.readCookie(csrfCookie); v != "" {
		wv.csrfVal = v
		return v
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	wv.csrfVal = base64.RawURLEncoding.EncodeToString(b)
	wv.csrfNew = true
	wv.setCookie(csrfCookie, wv.csrfVal, 0, true)
	return wv.csrfVal
}

// webPage is the shared view model.
type webPage struct {
	Title        string
	InstanceName string
	Desc         string
	Terms        string
	Privacy      string
	Contact      string
	Announce     string
	AnnounceWarn bool
	APIDocs      bool
	Base         string
	Authed       bool
	Admin        bool
	CSRF         string
	RequestID    string
	Data         any
}

// render executes the named page template.
func (wv *webReq) render(name string, status int, data any) {
	t := wv.web.tmpl[name]
	if t == nil {
		wv.errorPage(500)
		return
	}
	sv := wv.s.siteVals()
	pg := webPage{
		Title: name, InstanceName: sv.SiteName, Base: wv.web.link,
		Desc: sv.SiteDescription, Terms: sv.TermsURL, Privacy: sv.PrivacyURL,
		Contact: sv.Contact, APIDocs: wv.s.Cfg.Web.APIDocs,
		CSRF: wv.csrfToken(), RequestID: requestID(wv.r), Data: data,
	}
	wv.loadSession()
	if wv.sess != nil && wv.sess.Kind == meta.SessionFull {
		pg.Authed = true
		pg.Admin = wv.effectiveAdmin()
	}
	if sv.Maintenance {
		pg.Announce = sv.MaintenanceMsg
		pg.AnnounceWarn = true
	} else {
		pg.Announce = sv.Announcement
		pg.AnnounceWarn = sv.AnnouncementLvl == "warn"
	}
	h := wv.w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	wv.w.WriteHeader(status)
	if err := t.ExecuteTemplate(wv.w, "layout", pg); err != nil {
		wv.s.Log.Error("web render", "page", name, "err", err)
	}
}

// errorTitles and errorTexts keep error pages free of request data.
var errorPages = map[int][2]string{
	400: {"Bad request", "The request could not be understood."},
	403: {"Forbidden", "You do not have access to this page."},
	404: {"Not found", "The page you asked for does not exist."},
	405: {"Method not allowed", "This action is not allowed here."},
	413: {"Too large", "The request was too large."},
	421: {"Misdirected request", "This server does not serve that host."},
	429: {"Too many requests", "Slow down and try again in a moment."},
	500: {"Server error", "Something went wrong on our side."},
	503: {"Unavailable", "The service is busy. Try again shortly."},
}

// errorPage renders a styled error page.
func (wv *webReq) errorPage(code int) {
	tt, ok := errorPages[code]
	if !ok {
		code = 500
		tt = errorPages[500]
	}
	wv.render("error", code, struct {
		Status     int
		ErrorTitle string
		ErrorText  string
	}{code, tt[0], tt[1]})
}

// knownWebPrefixes are the authenticated path roots safeNext accepts.
var knownWebPrefixes = []string{"/account", "/admin"}

// safeNext validates a post-login redirect target.
func safeNext(next string) string {
	if len(next) == 0 || len(next) > 512 {
		return "/account"
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.HasPrefix(next, "/\\") || strings.Contains(next, "\\") {
		return "/account"
	}
	for _, r := range next {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return "/account"
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" || u.Scheme != "" {
		return "/account"
	}
	ok := false
	for _, p := range knownWebPrefixes {
		if u.Path == p || strings.HasPrefix(u.Path, p+"/") {
			ok = true
			break
		}
	}
	if !ok {
		return "/account"
	}
	return next
}

// --- static assets ---

var staticTypes = map[string]string{
	".woff2": "font/woff2",
	".svg":   "image/svg+xml",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
}

func (s *Server) whStatic(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	name := r.PathValue("name")
	if strings.Contains(name, "..") {
		wv.errorPage(404)
		return
	}
	// Exact-name assets (fonts, textures, svg) serve under their
	// embedded name; css and js accept a fingerprint segment.
	bare := name
	versioned := true
	if !strings.Contains(name, "/") {
		if i := strings.IndexByte(name, '.'); i > 0 {
			parts := strings.Split(name, ".")
			cand := parts[0] + "." + parts[len(parts)-1]
			if cand != name {
				bare = cand
				versioned = false // fingerprinted url for css/js
			}
		}
	}
	ok := false
	for _, n := range webui.StaticNames() {
		if n == bare {
			ok = true
			break
		}
	}
	if !ok {
		wv.errorPage(404)
		return
	}
	b, err := webui.ReadStatic(bare)
	if err != nil {
		wv.errorPage(404)
		return
	}
	fp := webui.Fingerprint(bare)
	h := w.Header()
	ext := bare[strings.LastIndexByte(bare, '.'):]
	h.Set("Content-Type", staticTypes[ext])
	h.Set("ETag", `"`+fp+`"`)
	if versioned {
		// Fingerprinted css/js and explicitly versioned files cache
		// forever; a bare css or js request must revalidate.
		if name == bare && (ext == ".css" || ext == ".js") {
			h.Set("Cache-Control", "public, no-cache")
		} else {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		}
	} else {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if r.Header.Get("If-None-Match") == `"`+fp+`"` {
		w.WriteHeader(304)
		return
	}
	w.WriteHeader(200)
	_, _ = w.Write(b) // #nosec G705 -- serves an embedded static asset
}

func (s *Server) whRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = fmt.Fprint(w, "User-agent: *\nAllow: /$\nAllow: /docs\nAllow: /openapi.yaml\nDisallow: /\n")
}
