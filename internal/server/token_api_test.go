package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTokenCreateExpiryCIDR(t *testing.T) {
	f := setup(t)
	tok := f.tokenFor(t, "u", []string{"read", "write"}, nil)

	// expires_in
	r := f.do(t, "POST", "/v1/tokens", strings.NewReader(`{"name":"a","scopes":["read"],"expires_in":"720h"}`),
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	if r.StatusCode != 201 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("expires_in: %d %s", r.StatusCode, b)
	}
	r.Body.Close()
	// expires_at
	r = f.do(t, "POST", "/v1/tokens", strings.NewReader(`{"name":"b","scopes":["read"],"expires_at":"2028-01-01T00:00:00Z"}`),
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	if r.StatusCode != 201 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("expires_at: %d %s", r.StatusCode, b)
	}
	r.Body.Close()
	// both -> 400
	r = f.do(t, "POST", "/v1/tokens", strings.NewReader(`{"name":"c","scopes":["read"],"expires_at":"2028-01-01T00:00:00Z","expires_in":"1h"}`),
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	if r.StatusCode != 400 {
		t.Fatalf("both: %d", r.StatusCode)
	}
	r.Body.Close()
	// invalid expires_in -> 400 and no token created
	r = f.do(t, "POST", "/v1/tokens", strings.NewReader(`{"name":"d","scopes":["read"],"expires_in":"junk"}`),
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	if r.StatusCode != 400 {
		t.Fatalf("bad expires_in: %d", r.StatusCode)
	}
	r.Body.Close()
	r = f.do(t, "GET", "/v1/tokens", nil, map[string]string{"Authorization": "Bearer " + tok})
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if strings.Contains(string(b), `"name":"d"`) || strings.Contains(string(b), "secret_hash") || strings.Contains(string(b), "SecretHash") {
		t.Fatalf("list leaked secret or created bad token: %s", b)
	}
	// allowed_cidrs normalized and echoed
	r = f.do(t, "POST", "/v1/tokens", strings.NewReader(`{"name":"e","scopes":["read"],"allowed_cidrs":["10.0.0.5"]}`),
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	var created struct {
		AllowedCIDRs []string `json:"allowed_cidrs"`
		ID           string   `json:"id"`
	}
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatalf("%s", b)
	}
	if len(created.AllowedCIDRs) != 1 || created.AllowedCIDRs[0] != "10.0.0.5/32" {
		t.Fatalf("cidrs=%v", created.AllowedCIDRs)
	}
}

func createTok(t *testing.T, f *fixture, bearer, body string) (string, *http.Response) {
	r := f.do(t, "POST", "/v1/tokens", strings.NewReader(body),
		map[string]string{"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
	var out struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	_ = json.Unmarshal(b, &out)
	return out.Token, r
}

func TestTokenPatchEventsStats(t *testing.T) {
	f := setup(t)
	f.s2.Svc.AuditEnabled = true
	tok := f.tokenFor(t, "u", []string{"read", "write"}, nil)
	stranger := f.tokenFor(t, "stranger", []string{"read"}, nil)
	admin := f.tokenFor(t, "adm", []string{"admin"}, nil)

	full, r := createTok(t, f, tok, `{"name":"x","scopes":["read"]}`)
	if r.StatusCode != 201 || full == "" {
		t.Fatalf("create: %d", r.StatusCode)
	}
	var id struct {
		ID string `json:"id"`
	}
	// fetch id via list
	r2 := f.do(t, "GET", "/v1/tokens", nil, map[string]string{"Authorization": "Bearer " + tok})
	b, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	var list []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	_ = json.Unmarshal(b, &list)
	tid := ""
	for _, tk := range list {
		if tk.Name == "x" {
			tid = tk.ID
		}
	}
	if tid == "" {
		t.Fatalf("token not listed: %s", b)
	}
	_ = id
	// PATCH rename
	r = f.do(t, "PATCH", "/v1/tokens/"+tid, strings.NewReader(`{"name":"y"}`),
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	if r.StatusCode != 200 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("patch: %d %s", r.StatusCode, b)
	}
	r.Body.Close()
	// PATCH stranger -> 403
	r = f.do(t, "PATCH", "/v1/tokens/"+tid, strings.NewReader(`{"name":"z"}`),
		map[string]string{"Authorization": "Bearer " + stranger, "Content-Type": "application/json"})
	if r.StatusCode != 403 {
		t.Fatalf("stranger: %d", r.StatusCode)
	}
	r.Body.Close()
	// PATCH admin allowed
	r = f.do(t, "PATCH", "/v1/tokens/"+tid, strings.NewReader(`{"name":"z"}`),
		map[string]string{"Authorization": "Bearer " + admin, "Content-Type": "application/json"})
	if r.StatusCode != 200 {
		t.Fatalf("admin: %d", r.StatusCode)
	}
	r.Body.Close()
	// PATCH cidrs
	r = f.do(t, "PATCH", "/v1/tokens/"+tid, strings.NewReader(`{"allowed_cidrs":["10.0.0.0/8"]}`),
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	if r.StatusCode != 200 {
		t.Fatalf("cidr patch: %d", r.StatusCode)
	}
	r.Body.Close()
	// events: created and cidr_changed present
	r = f.do(t, "GET", "/v1/tokens/"+tid+"/events", nil, map[string]string{"Authorization": "Bearer " + tok})
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(b), "created") || !strings.Contains(string(b), "cidr_changed") {
		t.Fatalf("events: %s", b)
	}
	// kind filter
	r = f.do(t, "GET", "/v1/tokens/"+tid+"/events?kind=renamed", nil, map[string]string{"Authorization": "Bearer " + tok})
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(b), "renamed") {
		t.Fatalf("kind filter: %s", b)
	}
	// bad kind -> 400
	r = f.do(t, "GET", "/v1/tokens/"+tid+"/events?kind=bogus", nil, map[string]string{"Authorization": "Bearer " + tok})
	if r.StatusCode != 400 {
		t.Fatalf("bad kind: %d", r.StatusCode)
	}
	r.Body.Close()
	// stats shape
	r = f.do(t, "GET", "/v1/tokens/"+tid+"/stats", nil, map[string]string{"Authorization": "Bearer " + tok})
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(b), `"total_requests"`) {
		t.Fatalf("stats: %s", b)
	}
	// revoke then PATCH -> 409
	r = f.do(t, "DELETE", "/v1/tokens/"+tid, nil, map[string]string{"Authorization": "Bearer " + tok})
	r.Body.Close()
	r = f.do(t, "PATCH", "/v1/tokens/"+tid, strings.NewReader(`{"name":"q"}`),
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	if r.StatusCode != 409 {
		t.Fatalf("revoked patch: %d", r.StatusCode)
	}
	r.Body.Close()
}

func TestTokenCIDREnforceAPI(t *testing.T) {
	f := setup(t)
	tok := f.tokenFor(t, "u", []string{"read", "write"}, nil)
	full, _ := createTok(t, f, tok, `{"name":"c","scopes":["read"],"allowed_cidrs":["10.0.0.0/8"]}`)
	// restricted token from the test loopback: 401, same body as a bad token
	r1 := f.do(t, "GET", "/v1/tokens", nil, map[string]string{"Authorization": "Bearer " + full})
	b1, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	if r1.StatusCode != 401 {
		t.Fatalf("want 401 got %d", r1.StatusCode)
	}
	r2 := f.do(t, "GET", "/v1/tokens", nil, map[string]string{"Authorization": "Bearer sv1_nope_wrong"})
	b2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if string(b1) != string(b2) {
		t.Fatalf("denied body differs: %q vs %q", b1, b2)
	}
	// XFF cannot bypass from an untrusted peer
	r3 := f.do(t, "GET", "/v1/tokens", nil, map[string]string{
		"Authorization": "Bearer " + full, "X-Forwarded-For": "10.0.0.9"})
	if r3.StatusCode != 401 {
		t.Fatalf("XFF bypass: %d", r3.StatusCode)
	}
	r3.Body.Close()
}
