// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
)

func TestBanEffects(t *testing.T) {
	f := webSetup(t, nil)
	u := f.mkCred(t, "alice", "a very fine password", false)
	sess := f.login(t, "alice", "a very fine password")

	// ban: login shows suspended text and no session cookie
	if err := f.s2.Ban(context.Background(), "admin", u.ID, "spam", nil, false); err != nil {
		t.Fatal(err)
	}
	cc := f.getCSRFCookie(t)
	tok := unauthCSRF(t, f, cc.Value)
	resp, body := f.postForm(t, "/login", url.Values{
		"username": {"alice"}, "password": {"a very fine password"}, "csrf_token": {tok}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 200 || !strings.Contains(body, "suspended") {
		t.Fatalf("banned login: %d", resp.StatusCode)
	}
	// existing session dies
	r2, _ := f.get(t, "/account", sess)
	if r2.StatusCode != 303 {
		t.Fatalf("banned session alive: %d", r2.StatusCode)
	}
	// token auth 401 while banned
	id, _, tokStr, hash, _ := auth.GenerateToken()
	_ = f.m.CreateToken(context.Background(), meta.Token{ID: id, UserID: u.ID,
		SecretHash: hash, Scopes: []string{"read"}, CreatedAt: f.clock.Now()})
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	r3, _ := f.cli.Do(req)
	if r3 == nil || r3.StatusCode != 401 {
		t.Fatalf("banned token: %v", r3)
	}
	// wrong password still generic
	cc2 := f.getCSRFCookie(t)
	tok2 := unauthCSRF(t, f, cc2.Value)
	resp2, body2 := f.postForm(t, "/login", url.Values{
		"username": {"alice"}, "password": {"wrong pass"}, "csrf_token": {tok2}},
		[]*http.Cookie{cc2}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if strings.Contains(body2, "suspended") {
		t.Fatal("wrong password leaked suspension")
	}
	// unban restores
	if err := f.s2.Unban(context.Background(), "admin", u.ID); err != nil {
		t.Fatal(err)
	}
	_ = resp2
	if c := f.login(t, "alice", "a very fine password"); c == nil {
		t.Fatal("login after unban")
	}
}

func TestBanGuards(t *testing.T) {
	f := webSetup(t, nil)
	adm := f.mkCred(t, "root", "a very fine password", true)
	if err := f.s2.Ban(context.Background(), adm.ID, adm.ID, "x", nil, false); err == nil {
		t.Fatal("self ban allowed")
	}
	if err := f.s2.Ban(context.Background(), "other", adm.ID, "x", nil, false); err == nil {
		t.Fatal("last admin ban allowed")
	}
	u2 := f.mkCred(t, "u2", "a very fine password", false)
	if err := f.s2.Ban(context.Background(), "other", u2.ID, "x", nil, false); err != nil {
		t.Fatal(err)
	}
}

func TestExpireBansAndSetPassword(t *testing.T) {
	f := webSetup(t, nil)
	u := f.mkCred(t, "alice", "a very fine password", false)
	until := time.Now().Add(-time.Minute)
	_ = f.m.SetUserStatus(context.Background(), meta.UserStatus{UserID: u.ID,
		State: "banned", At: time.Now(), Until: &until})
	ids, err := f.m.ExpireBans(context.Background(), time.Now())
	if err != nil || len(ids) != 1 || ids[0] != u.ID {
		t.Fatalf("expire=%v %v", ids, err)
	}
	u2, _ := f.m.GetUser(context.Background(), u.ID)
	if u2.Disabled {
		t.Fatal("still disabled")
	}
	// admin set password
	f.s2.auditor = NewAuditor(f.m, f.clock.NowFunc())
	pw, err := f.s2.AdminSetPassword(context.Background(), "adm", u.ID, "", true)
	if err != nil || len(pw) != 20 {
		t.Fatalf("generated: %v", err)
	}
	c := f.login(t, "alice", pw)
	if c == nil {
		t.Fatal("new password does not work")
	}
	// old password fails
	cc := f.getCSRFCookie(t)
	tok := unauthCSRF(t, f, cc.Value)
	resp, _ := f.postForm(t, "/login", url.Values{
		"username": {"alice"}, "password": {"a very fine password"}, "csrf_token": {tok}},
		[]*http.Cookie{cc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 200 {
		t.Fatal("old password should fail")
	}
}

func TestIPBlockEnforce(t *testing.T) {
	f := webSetup(t, nil)
	// block covering the acting admin's own address is refused
	ctx := ctxWithIP(context.Background(), netip.MustParseAddr("127.0.0.1"))
	if err := f.s2.AddIPBlock(ctx, "adm", "127.0.0.0/8", "abuse", nil); err == nil {
		t.Fatal("self-overlap should be refused")
	}
	// block a different range, verify unaffected path works
	if err := f.s2.AddIPBlock(context.Background(), "adm", "192.0.2.0/24", "abuse", nil); err != nil {
		t.Fatal(err)
	}
	r, _ := f.get(t, "/login")
	if r.StatusCode != 200 {
		t.Fatal("unrelated ip should work")
	}
}
