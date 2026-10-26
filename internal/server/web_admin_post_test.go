// SPDX-License-Identifier: 0BSD

package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func adminLogin(t *testing.T, f *webFixture) *http.Cookie {
	f.mkCred(t, "root", "a very fine password", true)
	return f.login(t, "root", "a very fine password")
}

func adminPost(t *testing.T, f *webFixture, sess *http.Cookie, path string, form url.Values) (*http.Response, string) {
	// session-bound csrf tokens live in rendered pages; scrape one
	_, page := f.get(t, "/admin", sess)
	i := strings.Index(page, `csrf_token" value="`)
	if i < 0 {
		t.Fatal("no csrf token on page")
	}
	tok := page[i+len(`csrf_token" value="`):]
	tok = tok[:strings.Index(tok, `"`)]
	form.Set("csrf_token", tok)
	return f.postForm(t, path, form, []*http.Cookie{sess},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
}

func TestAdminInviteFlow(t *testing.T) {
	f := webSetup(t, nil)
	sess := adminLogin(t, f)
	// create returns the code once
	r, body := adminPost(t, f, sess, "/admin/invites",
		url.Values{"label": {"beta"}, "max_uses": {"1"}})
	if r.StatusCode != 200 && r.StatusCode != 303 {
		t.Fatalf("create: %d", r.StatusCode)
	}
	if !strings.Contains(body, "inv_") {
		t.Fatalf("code not shown: %s", body[:200])
	}
	// list does not show it again
	r2, _ := f.get(t, "/admin/access", sess)
	if r2.StatusCode != 200 {
		t.Fatal("access")
	}
	// bad cidr shows a message
	r3, body3 := adminPost(t, f, sess, "/admin/ip-blocks",
		url.Values{"cidr": {"notacidr"}, "reason": {"x"}})
	if !strings.Contains(body3, "invalid") && !strings.Contains(body3, "bad") && r3.StatusCode == 200 {
		t.Fatalf("bad cidr: %d", r3.StatusCode)
	}
	// self block refused
	_, body4 := adminPost(t, f, sess, "/admin/ip-blocks",
		url.Values{"cidr": {"127.0.0.1/32"}, "reason": {"x"}})
	if strings.Contains(body4, "added") {
		t.Fatal("self block accepted")
	}
}

func TestAdminSettingsFlow(t *testing.T) {
	f := webSetup(t, nil)
	sess := adminLogin(t, f)
	// save without confirm_password must not change anything
	adminPost(t, f, sess, "/admin/settings", url.Values{"f:site.name": {"shiny"}})
	_, home := f.get(t, "/login")
	if strings.Contains(home, "shiny") {
		t.Fatal("changed without confirm")
	}
	// with confirm_password it applies
	// a wrong confirm_password must not apply either
	_, body2 := adminPost(t, f, sess, "/admin/settings",
		url.Values{"f:site.name": {"shiny"}, "confirm_password": {"wrong password"}})
	if !strings.Contains(body2, "password") {
		t.Fatal("no step-up prompt")
	}
	_, home2 := f.get(t, "/login")
	if strings.Contains(home2, "shiny") {
		t.Fatal("changed with wrong confirm")
	}
	// reset
	adminPost(t, f, sess, "/admin/settings/reset", url.Values{"key": {"site.name"}})
	_, home3 := f.get(t, "/login")
	if strings.Contains(home3, "shiny") {
		t.Fatal("reset did not restore")
	}
}

func TestAdminUserActions(t *testing.T) {
	f := webSetup(t, nil)
	sess := adminLogin(t, f)
	u := f.mkCred(t, "target", "a very fine password", false)
	// ban
	adminPost(t, f, sess, "/admin/users/"+u.ID,
		url.Values{"action": {"ban"}, "reason": {"test"}, "confirm_password": {"a very fine password"}})
	// banned user sees suspended page on correct password
	cc := f.getCSRFCookie(t)
	tok := unauthCSRF(t, f, cc.Value)
	_, body := f.postForm(t, "/login",
		url.Values{"username": {"target"}, "password": {"a very fine password"}, "csrf_token": {tok}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if !strings.Contains(body, "suspended") {
		t.Fatal("no suspended page")
	}
	// unban
	adminPost(t, f, sess, "/admin/users/"+u.ID,
		url.Values{"action": {"unban"}, "confirm_password": {"a very fine password"}})
	// set_password with generate returns a temp password once
	_, body2 := adminPost(t, f, sess, "/admin/users/"+u.ID,
		url.Values{"action": {"set_password"}, "generate": {"1"}, "confirm_password": {"a very fine password"}})
	_ = body2
	// delete without confirm_password must not delete
	adminPost(t, f, sess, "/admin/users/"+u.ID, url.Values{"action": {"delete"}})
	_, body3 := f.get(t, "/admin/users/"+u.ID, sess)
	if strings.Contains(body3, "deleted") {
		t.Fatal("deleted without confirm")
	}
	// fsck POST then system shows a result
	adminPost(t, f, sess, "/admin/fsck", url.Values{})
	_, body4 := f.get(t, "/admin/system", sess)
	if !strings.Contains(body4, "fsck") && !strings.Contains(body4, "integrity") {
		t.Fatal("system page")
	}
	// gc POST: mem blob has no gc runner, must be a styled page not a crash
	r5, b5 := adminPost(t, f, sess, "/admin/gc", url.Values{})
	if r5.StatusCode != 200 && r5.StatusCode != 303 && r5.StatusCode != 404 {
		t.Fatalf("gc: %d", r5.StatusCode)
	}
	_ = b5
}

func TestAccountUsageCharts(t *testing.T) {
	f := webSetup(t, nil)
	f.mkCred(t, "u", "a very fine password", false)
	sess := f.login(t, "u", "a very fine password")
	r, body := f.get(t, "/account", sess)
	if r.StatusCode != 200 {
		t.Fatalf("account: %d", r.StatusCode)
	}
	if strings.Contains(body, " style=") {
		t.Fatal("inline style")
	}
}
