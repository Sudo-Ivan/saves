// SPDX-License-Identifier: 0BSD

package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

var adminPages = []struct{ path, want string }{
	{"/admin", "Overview"},
	{"/admin/users", "Users"},
	{"/admin/access", "Access"},
	{"/admin/settings", "Settings"},
	{"/admin/audit", "Audit"},

	{"/admin/security", "Security"},
	{"/admin/system", "System"},
}

func TestAdminConsoleAccess(t *testing.T) {
	f := webSetup(t, nil)
	_ = f.mkCred(t, "root", "a very fine password", true)
	usr := f.mkCred(t, "u", "a very fine password", false)
	adminSess := f.login(t, "root", "a very fine password")
	userSess := f.login(t, "u", "a very fine password")
	_ = usr
	for _, p := range adminPages {
		// unauthenticated redirects
		r, _ := f.get(t, p.path)
		if r.StatusCode != 303 {
			t.Fatalf("%s unauth: %d", p.path, r.StatusCode)
		}
		// non-admin 403
		r2, _ := f.get(t, p.path, userSess)
		if r2.StatusCode == 200 {
			t.Fatalf("%s non-admin 200", p.path)
		}
		// admin 200 with content
		r3, body := f.get(t, p.path, adminSess)
		if r3.StatusCode != 200 {
			t.Fatalf("%s admin: %d", p.path, r3.StatusCode)
		}
		if !strings.Contains(body, p.want) {
			t.Fatalf("%s missing %q", p.path, p.want)
		}
		// security headers
		if r3.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("%s no csp", p.path)
		}
		if strings.Contains(body, "style=") && strings.Contains(body, "<style") {
			t.Fatalf("%s inline style", p.path)
		}
	}
	// CSRF required on admin POSTs
	cc := f.getCSRFCookie(t)
	r4, _ := f.postForm(t, "/admin/ip-blocks", url.Values{"cidr": {"192.0.2.0/24"}},
		[]*http.Cookie{cc, adminSess}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if r4.StatusCode != 403 {
		t.Fatalf("no-csrf: %d", r4.StatusCode)
	}
}

func TestAdminUsersList(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "root", "a very fine password", true)
	adm := f.login(t, "root", "a very fine password")
	for i := 0; i < 28; i++ {
		f.mkCred(t, "user"+string(rune('a'+i%26))+string(rune('a'+i/26)), "a very fine password", false)
	}
	r, body := f.get(t, "/admin/users", adm)
	if r.StatusCode != 200 || !strings.Contains(body, "Users") {
		t.Fatal("list")
	}
	// junk params tolerated
	r2, _ := f.get(t, "/admin/users?sort=zzz&state=bogus", adm)
	if r2.StatusCode != 200 {
		t.Fatal("junk params")
	}
	// search
	r3, body3 := f.get(t, "/admin/users?q=useraa", adm)
	if r3.StatusCode != 200 || !strings.Contains(body3, "useraa") {
		t.Fatal("search")
	}
}

func TestAdminAuditPage(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "root", "a very fine password", true)
	adm := f.login(t, "root", "a very fine password")
	// a failed login writes an audit row (no username)
	cc := f.getCSRFCookie(t)
	tok := unauthCSRF(t, f, cc.Value)
	f.postForm(t, "/login", url.Values{
		"username": {"nosuch"}, "password": {"x"}, "csrf_token": {tok}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	r, body := f.get(t, "/admin/audit?action=login_fail", adm)
	if r.StatusCode != 200 {
		t.Fatal("audit page")
	}
	if strings.Contains(body, "nosuch") {
		t.Fatal("username leaked into audit page")
	}
	// CSV export
	r2, body2 := f.get(t, "/admin/audit.csv", adm)
	if r2.StatusCode != 200 || !strings.HasPrefix(r2.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv: %d %s", r2.StatusCode, r2.Header.Get("Content-Type"))
	}
	if !strings.Contains(body2, "login_fail") {
		t.Fatalf("csv rows: %s", body2)
	}
}
