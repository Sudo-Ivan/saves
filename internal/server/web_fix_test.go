// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/server/webui"
)

func cookieByName(resp *http.Response, suffix string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, suffix) {
			return c
		}
	}
	return nil
}

// TestWebCookieAttrs covers a-c of the review: prefixes, Secure, Path.
func TestWebCookieAttrs(t *testing.T) {
	// https public_url: __Host- prefix, Secure, Path=/.
	f := webSetup(t, func(c *config.Config) {
		c.Web.PublicURL = "https://saves.example.com"
	})
	f.host = "saves.example.com"
	f.mkCred(t, "u", "a very fine password", false)
	req, _ := http.NewRequest("GET", f.srv.URL+"/login", nil)
	req.Host = "saves.example.com"
	resp, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cc := cookieByName(resp, "csrf")
	if cc == nil || cc.Name != "__Host-csrf" || !cc.Secure || !cc.HttpOnly ||
		cc.SameSite != http.SameSiteStrictMode || cc.Path != "/" || cc.Domain != "" {
		t.Fatalf("csrf cookie %+v", cc)
	}
	// Login sets __Host-sess.
	tok := unauthCSRF(t, f, cc.Value)
	resp, _ = f.postForm(t, "/login", url.Values{
		"username": {"u"}, "password": {"a very fine password"}, "csrf_token": {tok}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	sc := cookieByName(resp, "sess")
	if sc == nil || sc.Name != "__Host-sess" || !sc.Secure || !sc.HttpOnly ||
		sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" {
		t.Fatalf("sess cookie %+v", sc)
	}
	// Logout expiry cookie keeps name+attrs.
	_, body := f.get(t, "/account/security", sc)
	ptok := ""
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		ptok = body[i+len(`name="csrf_token" value="`):]
		ptok = ptok[:strings.IndexByte(ptok, '"')]
	}
	req, _ = http.NewRequest("POST", f.srv.URL+"/logout",
		strings.NewReader("csrf_token="+ptok))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Host = "saves.example.com"
	req.AddCookie(sc)
	resp, err = f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	gone := cookieByName(resp, "sess")
	if gone == nil || gone.Name != "__Host-sess" || !gone.Secure || gone.Path != "/" {
		t.Fatalf("logout cookie %+v", gone)
	}

	// cookie_secure=never: plain names, no Secure.
	f = webSetup(t, func(c *config.Config) { c.Web.CookieSecure = "never" })
	resp, body = f.get(t, "/login")
	cc = cookieByName(resp, "csrf")
	if cc == nil || cc.Name != "csrf" || cc.Secure || cc.Path != "/" {
		t.Fatalf("insecure csrf %+v", cc)
	}
	_ = body

	// Trusted peer forwarded proto https gets Secure/__Host- cookies.
	f = webSetup(t, func(c *config.Config) {
		c.Proxy.TrustedCIDRs = []string{"127.0.0.1/32"}
	})
	req, _ = http.NewRequest("GET", f.srv.URL+"/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err = f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cc = cookieByName(resp, "csrf")
	if cc == nil || cc.Name != "__Host-csrf" || !cc.Secure {
		t.Fatalf("trusted fwd cookie %+v", cc)
	}
	// Untrusted peer: same header ignored.
	f = webSetup(t, nil)
	req, _ = http.NewRequest("GET", f.srv.URL+"/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err = f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cc = cookieByName(resp, "csrf")
	if cc == nil || cc.Name != "csrf" || cc.Secure {
		t.Fatalf("untrusted fwd cookie %+v", cc)
	}
}

// TestWebHomeAndRobots covers d: homepage renders, robots tag only off homepage.
func TestWebHomeAndRobots(t *testing.T) {
	f := webSetup(t, nil)
	resp, body := f.get(t, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, "saves") {
		t.Fatalf("home: %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Robots-Tag") != "" {
		t.Fatal("homepage must not be noindex")
	}
	resp, _ = f.get(t, "/login")
	if resp.Header.Get("X-Robots-Tag") != "noindex" {
		t.Fatal("login should be noindex")
	}
	// f: unauthenticated /account redirects to /login?next=%2Faccount.
	resp, _ = f.get(t, "/account")
	if resp.Header.Get("Location") != "/login?next=%2Faccount" {
		t.Fatalf("next redirect %q", resp.Header.Get("Location"))
	}
}

// TestWebOriginCSRF covers e: Origin instead of Sec-Fetch-Site.
func TestWebOriginCSRF(t *testing.T) {
	f := webSetup(t, func(c *config.Config) {
		c.Web.PublicURL = "https://saves.example.com"
	})
	f.host = "saves.example.com"
	f.mkCred(t, "u", "a very fine password", false)
	cc := f.getCSRFCookie(t)
	tok := unauthCSRF(t, f, cc.Value)
	post := func(origin string) *http.Response {
		req, _ := http.NewRequest("POST", f.srv.URL+"/login", strings.NewReader(url.Values{
			"username": {"u"}, "password": {"a very fine password"},
			"csrf_token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cc)
		req.Host = "saves.example.com"
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := f.cli.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := post("https://saves.example.com"); resp.StatusCode != 303 {
		t.Fatalf("origin ok: %d", resp.StatusCode)
	}
	if resp := post("https://evil.example"); resp.StatusCode != 403 {
		t.Fatalf("bad origin: %d", resp.StatusCode)
	}
	// http server too
	f2 := webSetup(t, nil)
	f2.mkCred(t, "u", "a very fine password", false)
	cc2 := f2.getCSRFCookie(t)
	tok2 := unauthCSRF(t, f2, cc2.Value)
	req, _ := http.NewRequest("POST", f2.srv.URL+"/login", strings.NewReader(url.Values{
		"username": {"u"}, "password": {"a very fine password"},
		"csrf_token": {tok2}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+req.Host)
	req.AddCookie(cc2)
	resp, err := f2.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Fatalf("http origin: %d", resp.StatusCode)
	}
}

// TestWebBasePath covers item 2: prefixed public_url links and cookies.
func TestWebBasePath(t *testing.T) {
	f := webSetup(t, func(c *config.Config) {
		c.Web.PublicURL = "https://saves.example.com/saves"
	})
	f.host = "saves.example.com"
	f.mkCred(t, "u", "a very fine password", false)
	get := func(path string, ck *http.Cookie) (*http.Response, string) {
		req, _ := http.NewRequest("GET", f.srv.URL+path, nil)
		req.Host = "saves.example.com"
		if ck != nil {
			req.AddCookie(ck)
		}
		resp, err := f.cli.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := readAll(resp)
		return resp, b
	}
	for _, p := range []string{"/saves/login", "/login"} {
		resp, body := get(p, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		if strings.Contains(body, `/saveslogin`) || strings.Contains(body, `action="/login`) {
			t.Fatalf("bad join in %s body", p)
		}
		if !strings.Contains(body, `action="/saves/login`) {
			t.Fatalf("form action not prefixed in %s", p)
		}
		cc := cookieByName(resp, "csrf")
		if cc == nil || cc.Name != "__Secure-csrf" || cc.Path != "/saves" || !cc.Secure {
			t.Fatalf("csrf %+v", cc)
		}
	}
	// Redirect Location uses prefix.
	resp, _ := get("/saves/account", nil)
	if resp.Header.Get("Location") != "/saves/login?next=%2Faccount" {
		t.Fatalf("loc %q", resp.Header.Get("Location"))
	}
	// Asset href carries prefix.
	_, body := get("/saves/login", nil)
	if !strings.Contains(body, `href="/saves/static/app.`) {
		t.Fatal("asset not prefixed")
	}
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// TestWebMustChangeFlow covers item 3 end to end.
func TestWebMustChangeFlow(t *testing.T) {
	f := webSetup(t, nil)
	u := f.mkCred(t, "u", "a very fine password", false)
	yes := true
	if err := f.m.UpdateCredential(context.Background(), u.ID,
		meta.CredentialPatch{MustChange: &yes}); err != nil {
		t.Fatal(err)
	}
	sc := f.login(t, "u", "a very fine password")
	resp, _ := f.get(t, "/account", sc)
	if loc := resp.Header.Get("Location"); loc != "/account/security" {
		t.Fatalf("must_change loc %q", loc)
	}
	// GET security works, password POST succeeds, then account works.
	_, body := f.get(t, "/account/security", sc)
	var ptok string
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		ptok = body[i+len(`name="csrf_token" value="`):]
		ptok = ptok[:strings.IndexByte(ptok, '"')]
	}
	resp, _ = f.postForm(t, "/account/security/password", url.Values{
		"csrf_token": {ptok}, "current": {"a very fine password"},
		"new": {"fresh pass phrase"}, "new2": {"fresh pass phrase"}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 303 {
		t.Fatalf("pw change: %d", resp.StatusCode)
	}
	resp, _ = f.get(t, "/account", sc)
	if resp.StatusCode != 200 {
		t.Fatalf("account after change: %d", resp.StatusCode)
	}
}

// TestWebAdminSelfBlock and demotion coverage for item 4.
func TestWebAdminSelfBlock(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "root", "root super password", true)
	adm := f.login(t, "root", "root super password")
	u, _ := f.m.GetUserBySubject(context.Background(), "sub:root")
	_, body := f.get(t, "/admin/users/"+u.ID, adm)
	var ptok string
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		ptok = body[i+len(`name="csrf_token" value="`):]
		ptok = ptok[:strings.IndexByte(ptok, '"')]
	}
	resp, body2 := f.postForm(t, "/admin/users/"+u.ID, url.Values{
		"csrf_token": {ptok}, "action": {"disable"}},
		[]*http.Cookie{adm}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 200 || !strings.Contains(body2, "own account") {
		t.Fatalf("self disable: %d", resp.StatusCode)
	}
	// Demote the credential: existing session loses admin immediately.
	no := false
	if err := f.m.UpdateCredential(context.Background(), u.ID,
		meta.CredentialPatch{Admin: &no}); err != nil {
		t.Fatal(err)
	}
	resp, _ = f.get(t, "/admin", adm)
	if resp.StatusCode != 403 {
		t.Fatalf("demoted session reached /admin: %d", resp.StatusCode)
	}
}

// TestWebTOTPReenroll covers item 5.
func TestWebTOTPReenroll(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "u", "a very fine password", false)
	sc := f.login(t, "u", "a very fine password")
	resp, body := f.get(t, "/account/security/2fa", sc)
	if resp.StatusCode != 200 {
		t.Fatal("setup get")
	}
	var enroll, ptok, secret string
	if i := strings.Index(body, `name="enroll" value="`); i >= 0 {
		enroll = body[i+len(`name="enroll" value="`):]
		enroll = enroll[:strings.IndexByte(enroll, '"')]
	}
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		ptok = body[i+len(`name="csrf_token" value="`):]
		ptok = ptok[:strings.IndexByte(ptok, '"')]
	}
	if i := strings.Index(body, "Secret: <code>"); i >= 0 {
		secret = body[i+len("Secret: <code>"):]
		secret = secret[:strings.IndexByte(secret, '<')]
	}
	sec, _ := auth.ParseTOTPSecret(secret)
	resp, body = f.postForm(t, "/account/security/2fa", url.Values{
		"csrf_token": {ptok}, "enroll": {enroll},
		"code": {auth.TOTPCode(sec, f.clock.Now())}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 200 || !strings.Contains(body, "enabled") {
		t.Fatal("enroll")
	}
	// Already enabled: setup redirects back.
	resp, _ = f.get(t, "/account/security/2fa", sc)
	if resp.StatusCode != 303 {
		t.Fatalf("re-enroll not blocked: %d", resp.StatusCode)
	}
	// Stale enroll blob expired after 20 minutes.
	f.clock.Add(20 * time.Minute)
	resp, _ = f.postForm(t, "/account/security/2fa", url.Values{
		"csrf_token": {ptok}, "enroll": {enroll},
		"code": {auth.TOTPCode(sec, f.clock.Now())}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 303 {
		t.Fatalf("stale enroll: %d", resp.StatusCode)
	}
}

// TestWebRouteSweep covers item 8.
func TestWebRouteSweep(t *testing.T) {
	f := webSetup(t, func(c *config.Config) {
		c.Web.PublicURL = "https://saves.example.com"
	})
	f.host = "saves.example.com"
	f.mkCred(t, "u", "a very fine password", false)
	f.mkCred(t, "root", "root super password", true)
	sc := f.login(t, "u", "a very fine password")
	adm := f.login(t, "root", "root super password")
	for _, rt := range f.s2.web.routeList {
		if rt.Method != "GET" {
			continue
		}
		path := rt.Pattern
		for _, sub := range map[string]string{"{app}": "myapp", "{slot}": "myslot",
			"{id}": "x", "{hash}": "abcd"} {
			path = strings.ReplaceAll(path, sub, "")
		}
		path = strings.ReplaceAll(path, "snapshots/x/archive.tar", "snapshots/x/archive.tar")
		var ck *http.Cookie
		if strings.HasPrefix(path, "/account") {
			ck = sc
		} else if strings.HasPrefix(path, "/admin") {
			ck = adm
		}
		req, _ := http.NewRequest("GET", f.srv.URL+path, nil)
		req.Host = "saves.example.com"
		if ck != nil {
			req.AddCookie(ck)
		}
		resp, err := f.cli.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("%s %s: %d", rt.Method, rt.Pattern, resp.StatusCode)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("%s missing CSP", rt.Pattern)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s leaks CORS", rt.Pattern)
		}
	}
}

// TestWebNoSecretsInLog covers item 7 slog capture across flows.
func TestWebNoSecretsInLog(t *testing.T) {
	var sb strings.Builder
	h := slog.NewTextHandler(&sb, &slog.HandlerOptions{Level: slog.LevelDebug})
	orig := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(orig)

	f, idp := oidcFixture(t, func(c *config.Config) { c.Web.OIDC.AutoProvision = true })
	f.s2.Log = slog.New(h)
	f.mkCred(t, "u", "super secret pass", false)
	f.mkCred(t, "root", "root super password", true)
	sc := f.login(t, "u", "super secret pass")
	adm := f.login(t, "root", "root super password")

	// Password change.
	_, body := f.get(t, "/account/security", sc)
	ptok := csrfOf(body)
	f.postForm(t, "/account/security/password", url.Values{
		"csrf_token": {ptok}, "current": {"super secret pass"},
		"new": {"other secret pass"}, "new2": {"other secret pass"}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})

	// TOTP enrollment.
	_, body = f.get(t, "/account/security/2fa", sc)
	var enroll, secretB32 string
	if i := strings.Index(body, `name="enroll" value="`); i >= 0 {
		enroll = body[i+len(`name="enroll" value="`):]
		enroll = enroll[:strings.IndexByte(enroll, '"')]
	}
	if i := strings.Index(body, "Secret: <code>"); i >= 0 {
		secretB32 = body[i+len("Secret: <code>"):]
		secretB32 = secretB32[:strings.IndexByte(secretB32, '<')]
	}
	sec, err := auth.ParseTOTPSecret(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := f.postForm(t, "/account/security/2fa", url.Values{
		"csrf_token": {csrfOf(body)}, "enroll": {enroll},
		"code": {auth.TOTPCode(sec, f.clock.Now())}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	var recCode string
	if i := strings.Index(body, `code-list__item`); i >= 0 {
		j := strings.Index(body[i:], "<code>")
		recCode = body[i+j+6:]
		recCode = recCode[:strings.IndexByte(recCode, '<')]
	}
	_ = resp

	// TOTP login and recovery login.
	f.clock.Add(45 * time.Second)
	loginPending := func() *http.Cookie {
		cc := f.getCSRFCookie(t)
		ut := unauthCSRF(t, f, cc.Value)
		resp, _ := f.postForm(t, "/login", url.Values{
			"username": {"u"}, "password": {"other secret pass"}, "csrf_token": {ut}},
			[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
		return sessionCookieOf(resp)
	}
	pending := loginPending()
	_, body = f.get(t, "/login/2fa", pending)
	totpCode := auth.TOTPCode(sec, f.clock.Now())
	f.postForm(t, "/login/2fa", url.Values{
		"csrf_token": {csrfOf(body)}, "code": {totpCode}},
		[]*http.Cookie{pending}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	pending = loginPending()
	_, body = f.get(t, "/login/2fa", pending)
	f.postForm(t, "/login/2fa", url.Values{
		"csrf_token": {csrfOf(body)}, "recovery": {recCode}},
		[]*http.Cookie{pending}, map[string]string{"Sec-Fetch-Site": "same-origin"})

	// Token creation: the sv1_ secret is rendered once, never logged.
	sc2 := f.login(t, "u", "other secret pass")
	f.clock.Add(40 * time.Second) // fresh TOTP step
	pending2 := loginPending()
	_, body = f.get(t, "/login/2fa", pending2)
	resp, _ = f.postForm(t, "/login/2fa", url.Values{
		"csrf_token": {csrfOf(body)}, "code": {auth.TOTPCode(sec, f.clock.Now())}},
		[]*http.Cookie{pending2}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if full := sessionCookieOf(resp); full != nil {
		sc2 = full
	}
	_, body = f.get(t, "/account/tokens", sc2)
	_, body = f.postForm(t, "/account/tokens", url.Values{
		"csrf_token": {csrfOf(body)}, "name": {"t1"}, "scope_read": {"1"}, "scope_write": {"1"}},
		[]*http.Cookie{sc2}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	var sv1 string
	if i := strings.Index(body, "sv1_"); i >= 0 {
		j := strings.Index(body[i:], "<")
		sv1 = body[i : i+j]
	}
	if sv1 == "" {
		t.Fatal("token secret not rendered")
	}

	// Admin action.
	ru, _ := f.m.GetUserBySubject(context.Background(), "sub:root")
	u2, _ := f.m.GetUserBySubject(context.Background(), "sub:u")
	_, body = f.get(t, "/admin/users/"+u2.ID, adm)
	f.postForm(t, "/admin/users/"+u2.ID, url.Values{
		"csrf_token": {csrfOf(body)}, "action": {"revoke_sessions"}},
		[]*http.Cookie{adm}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	_ = ru

	// OIDC login through the fake IdP.
	f.s2.Cfg.Web.PublicURL = f.srv.URL
	oidcResp, oidcCk := oidcLogin(t, f, idp)
	_ = oidcResp

	out := sb.String()
	for _, bad := range []string{
		"super secret pass", "other secret pass", "root super password",
		sc.Value, adm.Value, pending.Value, oidcCk.Value,
		ptok, secretB32, string(sec), totpCode, recCode,
		"0123456789abcdef0123456789abcdef", sv1,
		idp.nonce, idp.chal, "oidc-sub-secret",
	} {
		if bad != "" && strings.Contains(out, bad) {
			t.Fatalf("log contains secret %q in %s", bad, out)
		}
	}
	if strings.Contains(out, "id_token") || strings.Contains(out, "code_verifier") {
		t.Fatal("log mentions oidc secret material")
	}
}

// csrfOf extracts the first masked csrf token from a page body.
func csrfOf(body string) string {
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		tok := body[i+len(`name="csrf_token" value="`):]
		return tok[:strings.IndexByte(tok, '"')]
	}
	return ""
}

// TestWebStaticAssets covers fingerprinting, versioned files and
// traversal for the extended static handler.
func TestWebStaticAssets(t *testing.T) {
	f := webSetup(t, nil)
	// Fingerprinted css is immutable.
	resp, _ := f.get(t, "/static/app."+webui.Fingerprint("app.css")+".css")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("fp css: %d", resp.StatusCode)
	}
	et := resp.Header.Get("ETag")
	// Bare css must revalidate.
	resp, _ = f.get(t, "/static/app.css")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "no-cache") {
		t.Fatalf("bare css: %d %s", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	// ETag revalidation gives 304.
	req, _ := http.NewRequest("GET", f.srv.URL+"/static/app.css", nil)
	req.Header.Set("If-None-Match", et)
	resp2, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 304 {
		t.Fatalf("etag: %d", resp2.StatusCode)
	}
	// Versioned font serves immutable with the font type.
	resp, _ = f.get(t, "/static/fonts/geist-mono-400-v1.woff2")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "font/woff2" ||
		!strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("font: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	// Texture svg serves.
	resp, _ = f.get(t, "/static/cotton-v1.svg")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("svg: %d", resp.StatusCode)
	}
	// Unknown file and traversal both 404.
	for _, p := range []string{"/static/nope.css", "/static/..%2Fconfig.json", "/static/fonts/nope.woff2"} {
		resp, _ = f.get(t, p)
		if resp.StatusCode != 404 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
}

// TestWebMustChangePlusForced2FA covers the deadlock: a must_change admin
// under require_2fa_admin used to bounce between security and 2fa setup.
// Now the password change completes first, then the 2FA gate applies.
func TestWebMustChangePlusForced2FA(t *testing.T) {
	f := webSetup(t, func(c *config.Config) { c.Web.Require2FAAdmin = true })
	u := f.mkCred(t, "a", "a very fine password", true)
	yes := true
	if err := f.m.UpdateCredential(context.Background(), u.ID,
		meta.CredentialPatch{MustChange: &yes}); err != nil {
		t.Fatal(err)
	}
	sc := f.login(t, "a", "a very fine password")
	resp, _ := f.get(t, "/account/security", sc)
	if resp.StatusCode != 200 {
		t.Fatalf("security for must_change: %d", resp.StatusCode)
	}
	// Change password; then the 2FA gate redirects to setup.
	_, body := f.get(t, "/account/security", sc)
	var ptok string
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		ptok = body[i+len(`name="csrf_token" value="`):]
		ptok = ptok[:strings.IndexByte(ptok, '"')]
	}
	resp, _ = f.postForm(t, "/account/security/password", url.Values{
		"csrf_token": {ptok}, "current": {"a very fine password"},
		"new": {"a second fine password"}, "new2": {"a second fine password"}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 303 {
		t.Fatalf("pw change: %d", resp.StatusCode)
	}
	resp, _ = f.get(t, "/account", sc)
	if loc := resp.Header.Get("Location"); loc != "/account/security/2fa" {
		t.Fatalf("2fa gate loc %q", loc)
	}
	resp, _ = f.get(t, "/account/security/2fa", sc)
	if resp.StatusCode != 200 {
		t.Fatalf("2fa setup: %d", resp.StatusCode)
	}
}
