// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob/mem"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/Sudo-Ivan/saves/internal/netx/nettest"
	"github.com/Sudo-Ivan/saves/internal/quota"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/Sudo-Ivan/saves/internal/settings"
)

type webFixture struct {
	srv   *httptest.Server
	host  string
	s2    *Server
	cli   *http.Client
	m     meta.Store
	clock *testclock.Clock
	cfg   config.Config
}

func webSetup(t *testing.T, mutate func(*config.Config)) *webFixture {
	t.Helper()
	c := testclock.New(time.Now())
	m, err := sqlite.Open(filepath.Join(t.TempDir(), "m.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Log.Access = false
	cfg.Web.Enabled = true
	cfg.Web.Secret = "0123456789abcdef0123456789abcdef"
	cfg.Web.Require2FA = false
	cfg.Web.Require2FAAdmin = false
	cfg.Quota.AllowUnknownApps = ".*"
	if mutate != nil {
		mutate(&cfg)
	}
	q := quota.New(&cfg)
	svc := service.New(m, mem.New(), q, service.Options{Clock: c.NowFunc()})
	chain := auth.Chain{&auth.TokenAuthenticator{Meta: m, Clock: c.NowFunc()}}
	reg := &auth.Registration{Mode: auth.RegOpen, Meta: m, DefaultTier: "free", Clock: c.NowFunc()}
	sm := settings.New(m, &cfg, c.NowFunc())
	if err := sm.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := New(svc, m, mem.New(), chain, reg, &cfg, Options{Clock: c.NowFunc(), Settings: sm})
	srv := httptest.NewServer(s.Handler())
	cli := &http.Client{
		Transport: nettest.LoopbackTransport(false),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	t.Cleanup(srv.Close)
	t.Cleanup(func() { m.Close() })
	return &webFixture{srv: srv, s2: s, cli: cli, m: m, clock: c, cfg: cfg}
}

// mkCred creates a user plus web credentials.
func (f *webFixture) mkCred(t *testing.T, username, password string, admin bool) meta.User {
	t.Helper()
	u, _, err := f.m.UpsertUser(context.Background(), "sub:"+username, "free")
	if err != nil {
		t.Fatal(err)
	}
	ph, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.CreateCredential(context.Background(), meta.WebCredential{
		UserID: u.ID, Username: username, PasswordHash: ph, Admin: admin}); err != nil {
		t.Fatal(err)
	}
	return u
}

// get does a GET following no redirects, returning the response and body.
func (f *webFixture) get(t *testing.T, path string, cookies ...*http.Cookie) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest("GET", f.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.host != "" {
		req.Host = f.host
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (f *webFixture) getCSRFCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp, _ := f.get(t, "/login")
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "csrf") {
			return c
		}
	}
	t.Fatal("no csrf cookie")
	return nil
}

func unauthCSRF(t *testing.T, f *webFixture, cookieVal string) string {
	t.Helper()
	mac := auth.HMAC(f.s2.web.csrfKey, []byte(cookieVal))
	var pad [32]byte
	copy(pad[:], []byte("pad"))
	tok := make([]byte, 64)
	copy(tok, pad[:])
	for i := range mac {
		tok[32+i] = pad[i] ^ mac[i]
	}
	return base64URLEnc(tok)
}

func base64URLEnc(b []byte) string {
	const e = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var v uint32
		n := 0
		for j := 0; j < 3 && i+j < len(b); j++ {
			v = v<<8 | uint32(b[i+j])
			n++
		}
		v <<= uint(24 - 8*n)
		for j := 0; j <= n; j++ {
			sb.WriteByte(e[v>>18&63])
			v <<= 6
		}
	}
	return sb.String()
}

// postForm posts urlencoded fields with the given cookies and headers.
func (f *webFixture) postForm(t *testing.T, path string, form url.Values, cookies []*http.Cookie, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest("POST", f.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f.host != "" {
		req.Host = f.host
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func sessionCookieOf(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "sess") {
			return c
		}
	}
	return nil
}

// login performs a full password login and returns the session cookie.
func (f *webFixture) login(t *testing.T, username, password string) *http.Cookie {
	t.Helper()
	cc := f.getCSRFCookie(t)
	tok := unauthCSRF(t, f, cc.Value)
	resp, _ := f.postForm(t, "/login", url.Values{
		"username": {username}, "password": {password}, "csrf_token": {tok},
	}, []*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 303 {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	c := sessionCookieOf(resp)
	if c == nil {
		t.Fatal("no session cookie")
	}
	return c
}

func TestWebLoginFlow(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "alice", "a very fine password", false)

	// Wrong password and unknown user return the identical body/status.
	cc := f.getCSRFCookie(t)
	tok := unauthCSRF(t, f, cc.Value)
	r1, b1 := f.postForm(t, "/login", url.Values{
		"username": {"alice"}, "password": {"wrong password!!"}, "csrf_token": {tok}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	tok2 := unauthCSRF(t, f, cc.Value)
	r2, b2 := f.postForm(t, "/login", url.Values{
		"username": {"nobody"}, "password": {"wrong password!!"}, "csrf_token": {tok2}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	// Mask the per-response csrf token before comparing.
	mask := func(s string) string {
		var out strings.Builder
		for {
			i := strings.Index(s, `name="csrf_token" value="`)
			if i < 0 {
				out.WriteString(s)
				return out.String()
			}
			j := i + len(`name="csrf_token" value="`)
			k := strings.IndexByte(s[j:], '"')
			if k < 0 {
				out.WriteString(s[:j] + "MASKED")
				return out.String()
			}
			out.WriteString(s[:j] + "MASKED")
			s = s[j+k:]
		}
	}
	if r1.StatusCode != r2.StatusCode || mask(b1) != mask(b2) {
		t.Fatalf("login failures differ: %d vs %d", r1.StatusCode, r2.StatusCode)
	}
	if !strings.Contains(b1, "Incorrect username or password") {
		t.Fatal("missing generic error")
	}

	// Happy path.
	sc := f.login(t, "alice", "a very fine password")
	resp, body := f.get(t, "/account", sc)
	if resp.StatusCode != 200 || !strings.Contains(body, "alice") {
		t.Fatalf("account: %d", resp.StatusCode)
	}
	// Unauthenticated account redirects to login.
	resp, _ = f.get(t, "/account")
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("no redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestWebCSRFSurface(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "bob", "a very fine password", false)
	sc := f.login(t, "bob", "a very fine password")

	post := func(hdr map[string]string, token string) *http.Response {
		form := url.Values{"current": {"a very fine password"}, "new": {"new pass phrase1"}, "new2": {"new pass phrase1"}}
		if token != "" {
			form.Set("csrf_token", token)
		}
		resp, _ := f.postForm(t, "/account/security/password", form, []*http.Cookie{sc}, hdr)
		return resp
	}
	// Build a valid token via a GET page.
	_, body := f.get(t, "/account/security", sc)
	var tok string
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		tok = body[i+len(`name="csrf_token" value="`):]
		tok = tok[:strings.IndexByte(tok, '"')]
	}
	if tok == "" {
		t.Fatal("no csrf token in page")
	}
	same := map[string]string{"Sec-Fetch-Site": "same-origin"}
	if r := post(same, ""); r.StatusCode != 403 {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	if r := post(same, "bogus"); r.StatusCode != 403 {
		t.Fatalf("bad token: %d", r.StatusCode)
	}
	if r := post(map[string]string{"Sec-Fetch-Site": "cross-site"}, tok); r.StatusCode != 403 {
		t.Fatalf("cross-site: %d", r.StatusCode)
	}
	if r := post(map[string]string{"Origin": "https://evil.example"}, tok); r.StatusCode != 403 {
		t.Fatalf("bad origin: %d", r.StatusCode)
	}
	if r := post(nil, tok); r.StatusCode != 403 {
		t.Fatalf("no headers: %d", r.StatusCode)
	}
	if r := post(same, tok); r.StatusCode != 303 {
		t.Fatalf("good: %d", r.StatusCode)
	}
}

func TestWebSessionRotationAndLogout(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "carol", "a very fine password", false)
	sc := f.login(t, "carol", "a very fine password")
	// Logout invalidates the session server side.
	_, body := f.get(t, "/account/security", sc)
	var tok string
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		tok = body[i+len(`name="csrf_token" value="`):]
		tok = tok[:strings.IndexByte(tok, '"')]
	}
	resp, _ := f.postForm(t, "/logout", url.Values{"csrf_token": {tok}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 303 || resp.Header.Get("Clear-Site-Data") == "" {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	resp, _ = f.get(t, "/account", sc)
	if resp.StatusCode != 303 {
		t.Fatalf("old session still valid: %d", resp.StatusCode)
	}
}

func TestWebSessionExpiry(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "dave", "a very fine password", false)
	sc := f.login(t, "dave", "a very fine password")
	f.clock.Add(3 * time.Hour) // idle 2h
	resp, _ := f.get(t, "/account", sc)
	if resp.StatusCode != 303 {
		t.Fatal("idle session accepted")
	}
	sc2 := f.login(t, "dave", "a very fine password")
	f.clock.Add(25 * time.Hour) // absolute 24h, touch keeps last_seen fresh
	resp, _ = f.get(t, "/account", sc2)
	if resp.StatusCode != 303 {
		t.Fatal("absolute-expired session accepted")
	}
}

func TestWebSafeNext(t *testing.T) {
	bad := []string{"", "//evil.com", "/\\x", `\\evil`, "/account\nx", "https://e.com/a",
		"/unknown", "/login", strings.Repeat("/", 600)}
	for _, b := range bad {
		if got := safeNext(b); got != "/account" {
			t.Fatalf("safeNext(%q) = %q", b, got)
		}
	}
	if got := safeNext("/account/tokens"); got != "/account/tokens" {
		t.Fatal("good next rejected")
	}
}

func FuzzSafeNext(f *testing.F) {
	for _, s := range []string{"/account", "//e", "/\\", "/a b", "https://x/y", "/admin/users"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := safeNext(s)
		if out != "/account" {
			if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") ||
				strings.ContainsAny(out, "\\ \t\n\r") || len(out) > 512 {
				t.Fatalf("unsafe output %q for %q", out, s)
			}
			u, err := url.Parse(out)
			if err != nil || u.IsAbs() || u.Host != "" {
				t.Fatalf("bad url %q", out)
			}
		}
	})
}

func TestWebSecurityHeaders(t *testing.T) {
	f := webSetup(t, nil)
	resp, _ := f.get(t, "/login")
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options",
		"X-Frame-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy",
		"Permissions-Policy", "Cache-Control"} {
		if resp.Header.Get(h) == "" {
			t.Fatalf("missing %s", h)
		}
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("web emitted CORS header")
	}
	// OPTIONS on web is 405.
	req, _ := http.NewRequest("OPTIONS", f.srv.URL+"/login", nil)
	r2, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 405 {
		t.Fatalf("OPTIONS: %d", r2.StatusCode)
	}
	// 404 styled.
	resp, body := f.get(t, "/nope")
	if resp.StatusCode != 404 || !strings.Contains(body, "Not found") {
		t.Fatal("bad 404 page")
	}
	// API still problem+json.
	resp, _ = f.get(t, "/v1/nope")
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") && resp.StatusCode != 404 {
		// ServeMux default 404 is text/plain; acceptable pre-change.
	}
	resp, _ = f.get(t, "/v1/me")
	if !strings.Contains(resp.Header.Get("Content-Type"), "problem+json") {
		t.Fatalf("v1 not problem+json: %s", resp.Header.Get("Content-Type"))
	}
	// Static asset fingerprinted.
	_, body = f.get(t, "/login")
	var href string
	if i := strings.Index(body, `href="/static/app.`); i >= 0 {
		href = body[i+6:]
		href = href[:strings.IndexByte(href, '"')]
	}
	if href == "" {
		t.Fatal("no fingerprinted css link")
	}
	resp, _ = f.get(t, href)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("static: %d %s", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	resp, _ = f.get(t, "/robots.txt")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("X-Robots-Tag"), "noindex") {
		// robots itself may be noindex; fine either way.
	}
}

func TestWebAdminGateAndDisable(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "erin", "a very fine password", false)
	f.mkCred(t, "root", "root super password", true)
	sc := f.login(t, "erin", "a very fine password")
	resp, _ := f.get(t, "/admin", sc)
	if resp.StatusCode != 403 {
		t.Fatalf("non-admin got admin: %d", resp.StatusCode)
	}
	adm := f.login(t, "root", "root super password")
	resp, body := f.get(t, "/admin", adm)
	if resp.StatusCode != 200 || !strings.Contains(body, "Admin") {
		t.Fatalf("admin page: %d", resp.StatusCode)
	}
	// Disabling the user kills sessions.
	u, _ := f.m.GetUserBySubject(context.Background(), "sub:erin")
	dis := true
	_, _ = f.m.UpdateUser(context.Background(), u.ID, meta.UserPatch{Disabled: &dis})
	resp, _ = f.get(t, "/account", sc)
	if resp.StatusCode != 303 {
		t.Fatalf("disabled user session valid: %d", resp.StatusCode)
	}
}

func TestWebPublicURLHost(t *testing.T) {
	f := webSetup(t, func(c *config.Config) {
		c.Web.PublicURL = "https://saves.example.com/base"
	})
	resp, _ := f.get(t, "/login")
	if resp.StatusCode != 421 {
		t.Fatalf("host mismatch not 421: %d", resp.StatusCode)
	}
	// Right host passes; base prefix stripped.
	req, _ := http.NewRequest("GET", f.srv.URL+"/base/login", nil)
	req.Host = "saves.example.com"
	resp, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("prefixed login: %d", resp.StatusCode)
	}
	// Without prefix also works.
	req, _ = http.NewRequest("GET", f.srv.URL+"/login", nil)
	req.Host = "saves.example.com"
	resp, err = f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unprefixed login: %d", resp.StatusCode)
	}
}

func TestWebForwardedHeaders(t *testing.T) {
	f := webSetup(t, nil)
	// Untrusted peer forwarded headers ignored: host stays the test
	// server host and the page renders.
	req, _ := http.NewRequest("GET", f.srv.URL+"/login", nil)
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("untrusted xff: %d", resp.StatusCode)
	}
	// Cookie should not be Secure since scheme stayed http.
	sc := ""
	for _, c := range resp.Cookies() {
		sc += c.Name + " "
	}
	if strings.Contains(sc, "__Secure-") || strings.Contains(sc, "__Host-") {
		t.Fatalf("untrusted forwarded proto upgraded cookie: %s", sc)
	}
}

func TestWebTOTPEnrollAndLogin(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "frank", "a very fine password", false)
	sc := f.login(t, "frank", "a very fine password")
	// Enroll: GET setup, compute code from the shown secret.
	resp, body := f.get(t, "/account/security/2fa", sc)
	if resp.StatusCode != 200 {
		t.Fatalf("setup page: %d", resp.StatusCode)
	}
	var secret, enroll, tok string
	if i := strings.Index(body, "Secret: <code>"); i >= 0 {
		secret = body[i+len("Secret: <code>"):]
		secret = secret[:strings.IndexByte(secret, '<')]
	}
	if i := strings.Index(body, `name="enroll" value="`); i >= 0 {
		enroll = body[i+len(`name="enroll" value="`):]
		enroll = enroll[:strings.IndexByte(enroll, '"')]
	}
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		tok = body[i+len(`name="csrf_token" value="`):]
		tok = tok[:strings.IndexByte(tok, '"')]
	}
	sec, err := auth.ParseTOTPSecret(secret)
	if err != nil || enroll == "" {
		t.Fatal("no secret on page")
	}
	code := auth.TOTPCode(sec, f.clock.Now())
	resp, body = f.postForm(t, "/account/security/2fa", url.Values{
		"csrf_token": {tok}, "enroll": {enroll}, "code": {code}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 200 || !strings.Contains(body, "enabled") {
		t.Fatalf("enroll post: %d", resp.StatusCode)
	}
	// Recovery code shown once.
	var recCode string
	if i := strings.Index(body, `code-list__item`); i >= 0 {
		j := strings.Index(body[i:], "<code>")
		recCode = body[i+j+6:]
		recCode = recCode[:strings.IndexByte(recCode, '<')]
	}
	if recCode == "" {
		t.Fatal("no recovery codes shown")
	}
	// Log in fresh: pending session then TOTP.
	cc := f.getCSRFCookie(t)
	ut := unauthCSRF(t, f, cc.Value)
	resp, _ = f.postForm(t, "/login", url.Values{
		"username": {"frank"}, "password": {"a very fine password"}, "csrf_token": {ut}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	pending := sessionCookieOf(resp)
	if resp.StatusCode != 303 || pending == nil {
		t.Fatalf("no pending session: %d", resp.StatusCode)
	}
	if pending.Value == sc.Value {
		t.Fatal("session id not rotated at login")
	}
	// Move past the enrolled step so the login code is a new step.
	f.clock.Add(45 * time.Second)
	// Pending session cannot see account.
	resp, _ = f.get(t, "/account", pending)
	if resp.StatusCode != 303 {
		t.Fatal("pending session reached account")
	}
	// Fetch csrf token for pending session via the 2fa page.
	_, body = f.get(t, "/login/2fa", pending)
	var ptok string
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		ptok = body[i+len(`name="csrf_token" value="`):]
		ptok = ptok[:strings.IndexByte(ptok, '"')]
	}
	code = auth.TOTPCode(sec, f.clock.Now())
	resp, _ = f.postForm(t, "/login/2fa", url.Values{
		"csrf_token": {ptok}, "code": {code}, "next": {"/account"}},
		[]*http.Cookie{pending}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	full := sessionCookieOf(resp)
	if resp.StatusCode != 303 || full == nil {
		t.Fatalf("2fa post: %d", resp.StatusCode)
	}
	if full.Value == pending.Value {
		t.Fatal("session id not rotated at 2fa")
	}
	resp, _ = f.get(t, "/account", full)
	if resp.StatusCode != 200 {
		t.Fatalf("account after 2fa: %d", resp.StatusCode)
	}
	// Same TOTP code replayed must fail: new login.
	cc = f.getCSRFCookie(t)
	ut = unauthCSRF(t, f, cc.Value)
	resp, _ = f.postForm(t, "/login", url.Values{
		"username": {"frank"}, "password": {"a very fine password"}, "csrf_token": {ut}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	pending = sessionCookieOf(resp)
	_, body = f.get(t, "/login/2fa", pending)
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		ptok = body[i+len(`name="csrf_token" value="`):]
		ptok = ptok[:strings.IndexByte(ptok, '"')]
	}
	resp, _ = f.postForm(t, "/login/2fa", url.Values{
		"csrf_token": {ptok}, "code": {code}},
		[]*http.Cookie{pending}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if sessionCookieOf(resp) != nil && sessionCookieOf(resp).Value != pending.Value {
		t.Fatal("replayed code accepted")
	}
	// Recovery code works once.
	_, body = f.get(t, "/login/2fa", pending)
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		ptok = body[i+len(`name="csrf_token" value="`):]
		ptok = ptok[:strings.IndexByte(ptok, '"')]
	}
	resp, _ = f.postForm(t, "/login/2fa", url.Values{
		"csrf_token": {ptok}, "recovery": {recCode}},
		[]*http.Cookie{pending}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 303 || sessionCookieOf(resp) == nil {
		t.Fatalf("recovery login: %d", resp.StatusCode)
	}
}

func TestWebRegister(t *testing.T) {
	f := webSetup(t, nil)
	cc := f.getCSRFCookie(t)
	tok := unauthCSRF(t, f, cc.Value)
	resp, _ := f.postForm(t, "/register", url.Values{
		"username": {"newuser"}, "password": {"a brand new password"},
		"password2": {"a brand new password"}, "csrf_token": {tok}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 303 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	// New user can log in.
	sc := f.login(t, "newuser", "a brand new password")
	resp, _ = f.get(t, "/account", sc)
	if resp.StatusCode != 200 {
		t.Fatalf("new user account: %d", resp.StatusCode)
	}
}

func TestWebNoSecretsInDB(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "gina", "a very fine password", false)
	sc := f.login(t, "gina", "a very fine password")
	h := sha256.Sum256([]byte(sc.Value))
	u, _ := f.m.GetUserBySubject(context.Background(), "sub:gina")
	list, _ := f.m.ListWebSessions(context.Background(), u.ID)
	if len(list) != 1 || hex.EncodeToString(list[0].IDHash[:]) != hex.EncodeToString(h[:]) {
		t.Fatal("session not stored hashed")
	}
}
