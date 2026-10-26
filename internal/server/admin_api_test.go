// SPDX-License-Identifier: 0BSD

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func adminDo(t *testing.T, f *fixture, method, path, bearer, body string) (*http.Response, []byte) {
	t.Helper()
	hdr := map[string]string{"Content-Type": "application/json"}
	if bearer != "" {
		hdr["Authorization"] = "Bearer " + bearer
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := f.do(t, method, path, rd, hdr)
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return r, b
}

func userIDOf(t *testing.T, f *fixture, bearer string) string {
	t.Helper()
	_, b := adminDo(t, f, "GET", "/v1/me", bearer, "")
	var me struct {
		User struct{ ID string } `json:"user"`
	}
	if err := json.Unmarshal(b, &me); err != nil || me.User.ID == "" {
		t.Fatalf("me: %s", b)
	}
	return me.User.ID
}

func TestAdminAPIAuthz(t *testing.T) {
	f := setup(t)
	user := f.tokenFor(t, "plain", []string{"read", "write"}, nil)
	routes := []struct{ method, path, body string }{
		{"GET", "/v1/admin/settings", ""},
		{"PATCH", "/v1/admin/settings", `{}`},
		{"POST", "/v1/admin/users/x/ban", `{"reason":"r"}`},
		{"POST", "/v1/admin/users/x/unban", `{}`},
		{"POST", "/v1/admin/users/x/approve", `{}`},
		{"POST", "/v1/admin/users/x/reject", `{}`},
		{"POST", "/v1/admin/users/x/password", `{"generate":true}`},
		{"GET", "/v1/admin/invites", ""},
		{"POST", "/v1/admin/invites", `{}`},
		{"DELETE", "/v1/admin/invites/x", ""},
		{"GET", "/v1/admin/ip-blocks", ""},
		{"POST", "/v1/admin/ip-blocks", `{"cidr":"203.0.113.0/24"}`},
		{"DELETE", "/v1/admin/ip-blocks/x", ""},
		{"GET", "/v1/admin/audit", ""},
		{"GET", "/v1/admin/users", ""},
		{"GET", "/v1/admin/stats", ""},
	}
	for _, rt := range routes {
		if r, _ := adminDo(t, f, rt.method, rt.path, "", rt.body); r.StatusCode != 401 {
			t.Errorf("%s %s unauthenticated: %d", rt.method, rt.path, r.StatusCode)
		}
		if r, _ := adminDo(t, f, rt.method, rt.path, user, rt.body); r.StatusCode != 403 {
			t.Errorf("%s %s non-admin: %d", rt.method, rt.path, r.StatusCode)
		}
	}
}

func TestAdminAPIModeration(t *testing.T) {
	f := setup(t)
	admin := f.tokenFor(t, "boss", []string{"read", "write", "admin"}, nil)
	victim := f.tokenFor(t, "victim", []string{"read"}, nil)
	vid := userIDOf(t, f, victim)
	if r, _ := adminDo(t, f, "GET", "/v1/me", victim, ""); r.StatusCode != 200 {
		t.Fatalf("victim before ban: %d", r.StatusCode)
	}
	if r, b := adminDo(t, f, "POST", "/v1/admin/users/"+vid+"/ban", admin, `{"reason":"abuse"}`); r.StatusCode/100 != 2 {
		t.Fatalf("ban: %d %s", r.StatusCode, b)
	}
	if r, _ := adminDo(t, f, "GET", "/v1/me", victim, ""); r.StatusCode != 401 {
		t.Fatalf("victim while banned: %d", r.StatusCode)
	}
	if r, b := adminDo(t, f, "POST", "/v1/admin/users/"+vid+"/unban", admin, `{}`); r.StatusCode/100 != 2 {
		t.Fatalf("unban: %d %s", r.StatusCode, b)
	}
	if r, _ := adminDo(t, f, "GET", "/v1/me", victim, ""); r.StatusCode != 200 {
		t.Fatalf("victim after unban: %d", r.StatusCode)
	}
	aid := userIDOf(t, f, admin)
	if r, _ := adminDo(t, f, "POST", "/v1/admin/users/"+aid+"/ban", admin, `{"reason":"self"}`); r.StatusCode/100 == 2 {
		t.Fatalf("admin banned themselves: %d", r.StatusCode)
	}
}

func TestAdminAPIInvitesAndBlocks(t *testing.T) {
	f := setup(t)
	admin := f.tokenFor(t, "boss", []string{"read", "write", "admin"}, nil)
	r, b := adminDo(t, f, "POST", "/v1/admin/invites", admin, `{"label":"friends","max_uses":1}`)
	if r.StatusCode/100 != 2 {
		t.Fatalf("invite create: %d %s", r.StatusCode, b)
	}
	var inv struct {
		Code string `json:"code"`
		ID   string `json:"id"`
	}
	_ = json.Unmarshal(b, &inv)
	if inv.Code == "" {
		t.Fatalf("no code in %s", b)
	}
	_, lb := adminDo(t, f, "GET", "/v1/admin/invites", admin, "")
	if strings.Contains(string(lb), inv.Code) {
		t.Fatalf("invite list leaks the code: %s", lb)
	}
	r, b = adminDo(t, f, "POST", "/v1/admin/ip-blocks", admin, `{"cidr":"203.0.113.0/24","reason":"spam"}`)
	if r.StatusCode/100 != 2 {
		t.Fatalf("block create: %d %s", r.StatusCode, b)
	}
	if r, _ = adminDo(t, f, "POST", "/v1/admin/ip-blocks", admin, `{"cidr":"127.0.0.1/32"}`); r.StatusCode/100 == 2 {
		t.Fatalf("self block accepted")
	}
	if r, _ = adminDo(t, f, "POST", "/v1/admin/ip-blocks", admin, `{"cidr":"not-an-ip"}`); r.StatusCode != 400 {
		t.Fatalf("bad cidr: %d", r.StatusCode)
	}
	_, ab := adminDo(t, f, "GET", "/v1/admin/audit", admin, "")
	if !json.Valid(ab) {
		t.Fatalf("audit not json: %s", ab)
	}
}
