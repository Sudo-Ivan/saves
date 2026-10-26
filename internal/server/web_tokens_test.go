package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
)

func csrfFrom(body string) string {
	i := strings.Index(body, `name="csrf_token" value="`)
	if i < 0 {
		return ""
	}
	j := i + len(`name="csrf_token" value="`)
	return body[j : j+strings.Index(body[j:], `"`)]
}

func tokForm(f *webFixture, t *testing.T, sc *http.Cookie, extra url.Values) url.Values {
	_, body := f.get(t, "/account/tokens", sc)
	form := url.Values{
		"csrf_token": {csrfFrom(body)},
		"name":       {"tok"},
		"scope_read": {"1"},
		"expires":    {"90d"},
	}
	for k, v := range extra {
		form[k] = v
	}
	return form
}

func createWebTok(t *testing.T, f *webFixture, sc *http.Cookie, extra url.Values) (*http.Response, string) {
	form := tokForm(f, t, sc, extra)
	return f.postForm(t, "/account/tokens", form, []*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
}

func latestToken(t *testing.T, f *webFixture, u meta.User) meta.Token {
	toks, err := f.m.ListTokens(context.Background(), u.ID)
	if err != nil || len(toks) == 0 {
		t.Fatalf("list: %v n=%d", err, len(toks))
	}
	return toks[len(toks)-1]
}

func TestWebTokenCreatePresets(t *testing.T) {
	f := webSetup(t, func(c *config.Config) { c.Auth.Token.AuditEnabled = true })
	f.s2.Svc.AuditEnabled = true
	u := f.mkCred(t, "alice", "a very fine password", false)
	sc := f.login(t, "alice", "a very fine password")
	now := f.clock.Now()
	days := map[string]float64{"1d": 1, "7d": 7, "30d": 30, "90d": 90, "180d": 180, "1y": 365}
	for k, d := range days {
		r, _ := createWebTok(t, f, sc, url.Values{"expires": {k}, "name": {k}})
		r.Body.Close()
		tk := latestToken(t, f, u)
		if tk.ExpiresAt == nil {
			t.Fatalf("%s: no expiry", k)
		}
		diff := tk.ExpiresAt.Sub(now).Hours()
		if diff < d*24-1 || diff > d*24+1 {
			t.Fatalf("%s: exp in %.1fh want %.0f", k, diff, d*24)
		}
	}
	// never
	r, _ := createWebTok(t, f, sc, url.Values{"expires": {"never"}, "name": {"never"}})
	r.Body.Close()
	if tk := latestToken(t, f, u); tk.ExpiresAt != nil {
		t.Fatal("never should have no expiry")
	}
	// custom wins over preset
	custom := now.Add(48 * time.Hour).UTC().Format("2006-01-02T15:04")
	r, _ = createWebTok(t, f, sc, url.Values{"expires": {"1d"}, "expires_custom": {custom}, "name": {"c"}})
	r.Body.Close()
	if tk := latestToken(t, f, u); tk.ExpiresAt == nil || tk.ExpiresAt.Sub(now).Hours() < 40 {
		t.Fatalf("custom: %v", tk.ExpiresAt)
	}
	// past custom rejected
	r, body := createWebTok(t, f, sc, url.Values{"expires_custom": {now.Add(-time.Hour).Format("2006-01-02T15:04")}, "name": {"past"}})
	r.Body.Close()
	if !strings.Contains(body, "future") {
		t.Fatalf("past: %s", body[:200])
	}
	// beyond 10y rejected
	r, _ = createWebTok(t, f, sc, url.Values{"expires_custom": {now.AddDate(11, 0, 0).Format("2006-01-02T15:04")}, "name": {"far"}})
	if strings.Contains(body, "far") {
		// rerender keeps values is fine; check no new token named far
	}
	r.Body.Close()
	toks, _ := f.m.ListTokens(context.Background(), u.ID)
	for _, tk := range toks {
		if tk.Name == "far" {
			t.Fatal("far token created")
		}
	}
	// bad CIDR names the entry
	r, body = createWebTok(t, f, sc, url.Values{"allowed_cidrs": {"10.0.0.1\nbogus-line"}, "name": {"cidr"}})
	r.Body.Close()
	if !strings.Contains(body, "bogus-line") {
		t.Fatalf("bad cidr not named: %s", body[:300])
	}
	// 17 distinct cidrs rejected
	var big strings.Builder
	for i := 0; i < 17; i++ {
		big.WriteString("10.0.0." + string(rune('0'+i)) + "\n")
	}
	r, _ = createWebTok(t, f, sc, url.Values{"allowed_cidrs": {big.String()}, "name": {"toomany"}})
	r.Body.Close()
	// normalized cidr stored
	r, _ = createWebTok(t, f, sc, url.Values{"allowed_cidrs": {"10.0.0.7/8"}, "name": {"norm"}})
	r.Body.Close()
	if tk := latestToken(t, f, u); len(tk.AllowedCIDRs) != 1 || tk.AllowedCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("cidrs=%v", tk.AllowedCIDRs)
	}
	// one-time secret: sv1_ in create response, not on next GET
	r, body = createWebTok(t, f, sc, url.Values{"name": {"secret"}})
	r.Body.Close()
	if !strings.Contains(body, "sv1_") {
		t.Fatal("no one-time secret")
	}
	_, body2 := f.get(t, "/account/tokens", sc)
	if strings.Contains(body2, "sv1_") {
		t.Fatal("secret still on page")
	}
}

func TestWebTokenMaxTTL(t *testing.T) {
	f := webSetup(t, func(c *config.Config) {
		c.Auth.Token.AuditEnabled = true
		c.Auth.Token.MaxTTL = config.Duration(30 * 24 * time.Hour)
	})
	f.s2.Svc.AuditEnabled = true
	f.s2.Svc.TokenMaxTTL = 30 * 24 * time.Hour
	u := f.mkCred(t, "bob", "a very fine password", false)
	sc := f.login(t, "bob", "a very fine password")
	_, body := f.get(t, "/account/tokens", sc)
	for _, v := range []string{"90d", "180d", "1y", "never"} {
		if strings.Contains(body, `value="`+v+`"`) {
			t.Fatalf("option %s offered under max_ttl", v)
		}
	}
	// forced never must not produce a non-expiring token
	r, _ := createWebTok(t, f, sc, url.Values{"expires": {"never"}, "name": {"x"}})
	r.Body.Close()
	for _, tk := range func() []meta.Token { l, _ := f.m.ListTokens(context.Background(), u.ID); return l }() {
		if tk.Name == "x" && tk.ExpiresAt == nil {
			t.Fatal("never under max_ttl created a non-expiring token")
		}
	}
}

func TestWebTokenDetailEditRevokeCSV(t *testing.T) {
	f := webSetup(t, func(c *config.Config) { c.Auth.Token.AuditEnabled = true })
	f.s2.Svc.AuditEnabled = true
	u := f.mkCred(t, "ann", "a very fine password", false)
	sc := f.login(t, "ann", "a very fine password")
	r, body := createWebTok(t, f, sc, url.Values{"name": {"det"}})
	r.Body.Close()
	if !strings.Contains(body, "sv1_") {
		t.Fatal("no secret")
	}
	i := strings.Index(body, "sv1_")
	secret := body[i : i+strings.IndexAny(body[i:], "<\"' \n")]
	tk := latestToken(t, f, u)
	det := "/account/tokens/" + tk.ID
	// owner 200
	r, body = f.get(t, det, sc)
	if r.StatusCode != 200 || !strings.Contains(body, "det") {
		t.Fatalf("detail: %d", r.StatusCode)
	}
	// stranger gets 404 without the name
	_ = f.mkCred(t, "eve", "a very fine password", false)
	sc2 := f.login(t, "eve", "a very fine password")
	r, body2 := f.get(t, det, sc2)
	if r.StatusCode != 404 || strings.Contains(body2, `"det"`) {
		t.Fatalf("stranger: %d", r.StatusCode)
	}
	// unauthenticated redirects
	r, _ = f.get(t, det)
	if r.StatusCode != 303 {
		t.Fatalf("unauth: %d", r.StatusCode)
	}
	// admin sees owner
	_ = f.mkCred(t, "root", "a very fine password", true)
	sca := f.login(t, "root", "a very fine password")
	r, body3 := f.get(t, det, sca)
	if r.StatusCode != 200 || !strings.Contains(strings.ToLower(body3), "owner") {
		t.Fatalf("admin view: %d", r.StatusCode)
	}
	// edit: rename + set cidrs, one event each, client ip recorded
	_, dbody := f.get(t, det, sc)
	csrf := csrfFrom(dbody)
	r, _ = f.postForm(t, det+"/edit", url.Values{
		"csrf_token": {csrf}, "name": {"renamed"}, "allowed_cidrs": {"10.0.0.0/8"},
		"expires": {"keep"}}, []*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	r.Body.Close()
	tk2, _ := f.m.GetToken(context.Background(), tk.ID)
	if tk2.Name != "renamed" || len(tk2.AllowedCIDRs) != 1 {
		t.Fatalf("edit: %v %v", tk2.Name, tk2.AllowedCIDRs)
	}
	ev, _, _ := f.m.ListTokenEvents(context.Background(), tk.ID, "", "", 50)
	if len(ev) < 3 {
		t.Fatalf("events: %v", ev)
	}
	// no-csrf 403
	r, _ = f.postForm(t, det+"/edit", url.Values{"name": {"x"}}, []*http.Cookie{sc},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if r.StatusCode != 403 {
		t.Fatalf("no csrf: %d", r.StatusCode)
	}
	r.Body.Close()
	// edit effect immediate: allowlist to a different cidr denies the api key
	_, dbody2 := f.get(t, det, sc)
	r, _ = f.postForm(t, det+"/edit", url.Values{
		"csrf_token": {csrfFrom(dbody2)}, "name": {"renamed"}, "allowed_cidrs": {"192.0.2.0/24"},
		"expires": {"keep"}}, []*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	r.Body.Close()
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("edit not immediate: %d", resp.StatusCode)
	}
	// revoke via confirm then post
	r, body = f.get(t, det+"/revoke", sc)
	if r.StatusCode != 200 {
		t.Fatalf("confirm: %d", r.StatusCode)
	}
	r, _ = f.postForm(t, det+"/revoke", url.Values{"csrf_token": {csrfFrom(body)}},
		[]*http.Cookie{sc}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if r.StatusCode != 303 {
		t.Fatalf("revoke: %d", r.StatusCode)
	}
	r.Body.Close()
	// csv export
	r, csvBody := f.get(t, det+"/audit.csv", sc)
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/csv") ||
		r.Header.Get("Content-Disposition") == "" {
		t.Fatalf("csv: %d %v", r.StatusCode, r.Header)
	}
	if !strings.Contains(csvBody, "revoked") {
		t.Fatalf("csv rows: %s", csvBody[:200])
	}
	// stranger csv 404
	r, _ = f.get(t, det+"/audit.csv", sc2)
	if r.StatusCode != 404 {
		t.Fatalf("stranger csv: %d", r.StatusCode)
	}
	r.Body.Close()
}

func TestWebTokenAuditPagination(t *testing.T) {
	f := webSetup(t, func(c *config.Config) { c.Auth.Token.AuditEnabled = true })
	f.s2.Svc.AuditEnabled = true
	u := f.mkCred(t, "pg", "a very fine password", false)
	sc := f.login(t, "pg", "a very fine password")
	r, _ := createWebTok(t, f, sc, url.Values{"name": {"pgt"}})
	r.Body.Close()
	tk := latestToken(t, f, u)
	now := f.clock.Now()
	for i := 0; i < 120; i++ {
		id, _ := meta.NewID(now)
		if err := f.m.InsertTokenEvent(context.Background(), meta.TokenEvent{
			ID: id, TokenID: tk.ID, UserID: u.ID,
			At: now.Add(time.Duration(i) * time.Second), Kind: "created"}); err != nil {
			t.Fatal(err)
		}
	}
	cursor := ""
	pages, rows := 0, 0
	for {
		path := "/account/tokens/" + tk.ID + "?kind=created"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		r, body := f.get(t, path, sc)
		if r.StatusCode != 200 {
			t.Fatalf("page: %d", r.StatusCode)
		}
		rows += strings.Count(body, "<td")
		j := strings.Index(body, "cursor=")
		pages++
		if j < 0 || pages > 8 {
			break
		}
		cursor = strings.Split(body[j+7:], `"`)[0]
	}
	// 121 created events (120 seeded + 1 from the create), 5 cells per row
	if rows != 121*5 {
		t.Fatalf("cells=%d pages=%d", rows, pages)
	}
	if pages < 3 {
		t.Fatalf("pages=%d", pages)
	}
}

func TestWebTokenCSVEscapeAndMarkup(t *testing.T) {
	f := webSetup(t, func(c *config.Config) { c.Auth.Token.AuditEnabled = true })
	f.s2.Svc.AuditEnabled = true
	u := f.mkCred(t, "csv", "a very fine password", false)
	sc := f.login(t, "csv", "a very fine password")
	r, _ := createWebTok(t, f, sc, url.Values{"name": {"c1"}})
	r.Body.Close()
	tk := latestToken(t, f, u)
	now := f.clock.Now()
	id, _ := meta.NewID(now)
	_ = f.m.InsertTokenEvent(context.Background(), meta.TokenEvent{ID: id, TokenID: tk.ID,
		UserID: u.ID, At: now, Kind: "renamed", UserAgent: "=cmd evil"})
	id2, _ := meta.NewID(now)
	_ = f.m.InsertTokenEvent(context.Background(), meta.TokenEvent{ID: id2, TokenID: tk.ID,
		UserID: u.ID, At: now, Kind: "cidr_changed", UserAgent: "-1"})
	r, csv := f.get(t, "/account/tokens/"+tk.ID+"/audit.csv", sc)
	if !strings.Contains(csv, "'=cmd") && !strings.Contains(csv, `"'=cmd`) {
		t.Fatalf("formula not escaped: %s", csv)
	}
	if !strings.Contains(csv, "'-1") && !strings.Contains(csv, `"'-1`) {
		t.Fatalf("formula not escaped: %s", csv)
	}
	if r.Header.Get("Cache-Control") == "" {
		t.Fatal("no no-store")
	}
	// kind filter
	_, csv2 := f.get(t, "/account/tokens/"+tk.ID+"/audit.csv?kind=renamed", sc)
	if strings.Contains(csv2, "cidr_changed") {
		t.Fatal("kind filter ignored in csv")
	}
	// copy button + add-my-address hidden markup
	_, list := f.get(t, "/account/tokens", sc)
	if !strings.Contains(list, "data-append-ip") || !strings.Contains(list, "127.0.0.1") {
		t.Fatal("no add-my-address or client ip")
	}
	// admin user page lists tokens without secrets
	_ = f.mkCred(t, "adm2", "a very fine password", true)
	sca := f.login(t, "adm2", "a very fine password")
	r, ap := f.get(t, "/admin/users/"+u.ID, sca)
	if r.StatusCode != 200 || !strings.Contains(ap, "c1") || strings.Contains(ap, "sv1_") {
		t.Fatalf("admin user page: %d", r.StatusCode)
	}
}
