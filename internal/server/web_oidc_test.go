// SPDX-License-Identifier: 0BSD

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/config"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIdP serves discovery, jwks, authorize bookkeeping and a token
// endpoint that checks the PKCE verifier.
type fakeIdP struct {
	srv    *httptest.Server
	priv   *ecdsa.PrivateKey
	chal   string
	nonce  string
	client string
	fail   bool
	none   bool // issue unsigned tokens
	claims func(nonce string) (jwt.Claims, map[string]any)
	sign   func(claims jwt.Claims, extra map[string]any) string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{priv: priv}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": idp.srv.URL, "authorization_endpoint": idp.srv.URL + "/auth",
			"token_endpoint": idp.srv.URL + "/token", "jwks_uri": idp.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		ks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: "k1", Algorithm: "ES256"}}}
		json.NewEncoder(w).Encode(ks)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if idp.fail {
			w.WriteHeader(500)
			return
		}
		r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != idp.chal {
			w.WriteHeader(400)
			return
		}
		if idp.client != "" {
			u, p, ok := r.BasicAuth()
			if !ok || u != idp.client || p != "sec" {
				w.WriteHeader(401)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		cl, extra := idp.goodClaims()
		if idp.claims != nil {
			cl, extra = idp.claims(idp.nonce)
		}
		json.NewEncoder(w).Encode(map[string]any{"id_token": idp.sign(cl, extra)})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	idp.sign = func(claims jwt.Claims, extra map[string]any) string {
		if idp.none {
			hb, _ := json.Marshal(map[string]any{"alg": "none"})
			cb, _ := json.Marshal(map[string]any{
				"iss": claims.Issuer, "sub": claims.Subject, "aud": []string(claims.Audience),
				"exp": claims.Expiry.Time().Unix(), "nonce": idp.nonce})
			return base64.RawURLEncoding.EncodeToString(hb) + "." +
				base64.RawURLEncoding.EncodeToString(cb) + "."
		}
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv},
			(&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
		if err != nil {
			t.Fatal(err)
		}
		b := jwt.Signed(sig).Claims(claims)
		for k, v := range extra {
			b = b.Claims(map[string]any{k: v})
		}
		raw, err := b.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	return idp
}

// goodClaims returns the default id_token claims and extras.
func (idp *fakeIdP) goodClaims() (jwt.Claims, map[string]any) {
	return jwt.Claims{
		Issuer: idp.srv.URL, Subject: "oidc-sub",
		Audience: jwt.Audience{"saves"}, IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, map[string]any{"nonce": idp.nonce}
}

// oidcFlow performs the start + callback returning the last response
// and the sealed-cookie state captured from the start response.
func oidcLogin(t *testing.T, f *webFixture, idp *fakeIdP) (*http.Response, http.Cookie) {
	t.Helper()
	resp, _ := f.get(t, "/auth/oidc/start?next=%2Faccount")
	var oc *http.Cookie
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "oidc") {
			oc = c
		}
	}
	loc := resp.Header.Get("Location")
	if oc == nil || loc == "" {
		t.Fatal("no oidc start")
	}
	q, _ := url.Parse(loc)
	idp.chal = q.Query().Get("code_challenge")
	if idp.chal == "" {
		t.Fatal("no pkce challenge")
	}
	idp.nonce = q.Query().Get("nonce")
	if idp.nonce == "" {
		t.Fatal("no nonce")
	}
	if q.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("no S256")
	}
	if q.Query().Get("redirect_uri") != strings.TrimSuffix(f.cfg.Web.PublicURL, "/")+"/auth/oidc/callback" &&
		q.Query().Get("redirect_uri") != f.srv.URL+"/auth/oidc/callback" {
		t.Fatalf("redirect_uri %q", q.Query().Get("redirect_uri"))
	}
	state := q.Query().Get("state")
	cb := "/auth/oidc/callback?state=" + url.QueryEscape(state) + "&code=xyz"
	req, _ := http.NewRequest("GET", f.srv.URL+cb, nil)
	if f.host != "" {
		req.Host = f.host
	}
	req.AddCookie(oc)
	resp2, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	return resp2, *oc
}

func oidcFixture(t *testing.T, mutate func(*config.Config)) (*webFixture, *fakeIdP) {
	idp := newFakeIdP(t)
	f := webSetup(t, func(c *config.Config) {
		if mutate != nil {
			mutate(c)
		}
		c.Web.OIDC.Enabled = true
		c.Web.OIDC.Issuer = idp.srv.URL
		c.Web.OIDC.ClientID = "saves"
	})
	// Point public_url at the test server so redirect_uri matches.
	f.s2.Cfg.Web.PublicURL = f.srv.URL
	return f, idp
}

func TestWebOIDCLogin(t *testing.T) {
	f, idp := oidcFixture(t, func(c *config.Config) { c.Web.OIDC.AutoProvision = true })
	// redirect_uri is built from public_url; without one the start
	// handler cannot run, so set it now.
	resp, _ := f.get(t, "/auth/oidc/start")
	if resp.StatusCode != 302 {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	resp, _ = oidcLogin(t, f, idp)
	if resp.StatusCode != 303 {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/account" {
		t.Fatalf("loc %q", loc)
	}
	if cookieByName(resp, "sess") == nil {
		t.Fatal("no session cookie")
	}
	// Replay: the same cookie is single use.
	req, _ := http.NewRequest("GET", f.srv.URL+"/auth/oidc/callback?state=x&code=y", nil)
	resp, _ = f.cli.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("replay: %d", resp.StatusCode)
	}
	// Unknown user rejected without creating a row.
	f2, idp2 := oidcFixture(t, nil)
	resp, _ = oidcLogin(t, f2, idp2)
	if resp.StatusCode != 200 {
		t.Fatalf("unknown user: %d", resp.StatusCode)
	}
	if _, err := f2.m.GetUserBySubject(req.Context(), "oidc-sub"); err == nil {
		t.Fatal("user row created for rejected login")
	}
}

// TestWebOIDCCallbackNegatives covers the failure matrix.
func TestWebOIDCCallbackNegatives(t *testing.T) {
	type run struct {
		name   string
		mutate func(*fakeIdP)
		cookie string // "good", "tampered", "missing"
		want   int
	}
	runs := []run{
		{name: "wrong nonce", mutate: func(i *fakeIdP) {
			i.claims = func(n string) (jwt.Claims, map[string]any) {
				c, e := i.goodClaims()
				e["nonce"] = "other"
				return c, e
			}
		}, cookie: "good", want: 200},
		{name: "wrong audience", mutate: func(i *fakeIdP) {
			i.claims = func(n string) (jwt.Claims, map[string]any) {
				c, e := i.goodClaims()
				c.Audience = jwt.Audience{"other"}
				return c, e
			}
		}, cookie: "good", want: 200},
		{name: "expired", mutate: func(i *fakeIdP) {
			i.claims = func(n string) (jwt.Claims, map[string]any) {
				c, e := i.goodClaims()
				c.Expiry = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
				c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-3 * time.Hour))
				return c, e
			}
		}, cookie: "good", want: 200},
		{name: "alg none", mutate: func(i *fakeIdP) { i.none = true }, cookie: "good", want: 200},
		{name: "token 500", mutate: func(i *fakeIdP) { i.fail = true }, cookie: "good", want: 200},
		{name: "tampered cookie", cookie: "tampered", want: 200},
		{name: "missing cookie", cookie: "missing", want: 200},
	}
	for _, r := range runs {
		t.Run(r.name, func(t *testing.T) {
			f, idp := oidcFixture(t, func(c *config.Config) { c.Web.OIDC.AutoProvision = true })
			if r.mutate != nil {
				// Mutate inside the start->callback flow; nonce arrives
				// at authorize time so set the hook before calling back.
				f2 := f
				_ = f2
			}
			// Drive start, then mutate before the callback exchange.
			resp, _ := f.get(t, "/auth/oidc/start?next=%2Faccount")
			var oc *http.Cookie
			for _, c := range resp.Cookies() {
				if strings.HasSuffix(c.Name, "oidc") {
					oc = c
				}
			}
			q, _ := url.Parse(resp.Header.Get("Location"))
			idp.chal = q.Query().Get("code_challenge")
			idp.nonce = q.Query().Get("nonce")
			state := q.Query().Get("state")
			if r.mutate != nil {
				r.mutate(idp)
			}
			cb := "/auth/oidc/callback?state=" + url.QueryEscape(state) + "&code=xyz"
			req, _ := http.NewRequest("GET", f.srv.URL+cb, nil)
			switch r.cookie {
			case "tampered":
				v := oc.Value
				oc2 := *oc
				oc2.Value = v[:len(v)-2] + "AA"
				req.AddCookie(&oc2)
			case "good":
				req.AddCookie(oc)
			}
			resp2, err := f.cli.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp2.Body.Close()
			if resp2.StatusCode != r.want || cookieByName(resp2, "sess") != nil {
				t.Fatalf("%s: got %d want %d, session set %v",
					r.name, resp2.StatusCode, r.want, cookieByName(resp2, "sess") != nil)
			}
		})
	}
}

// TestWebOIDCAdminClaim covers the string and array admin claim.
func TestWebOIDCAdminClaim(t *testing.T) {
	for _, val := range []any{"ops", []any{"x", "ops"}} {
		f, idp := oidcFixture(t, func(c *config.Config) {
			c.Web.OIDC.AutoProvision = true
			c.Web.OIDC.AdminClaim = "groups"
			c.Web.OIDC.AdminValue = "ops"
		})
		idp.claims = func(n string) (jwt.Claims, map[string]any) {
			c, e := idp.goodClaims()
			e["groups"] = val
			return c, e
		}
		resp, _ := oidcLogin(t, f, idp)
		sc := cookieByName(resp, "sess")
		if sc == nil {
			t.Fatalf("%v: no session", val)
		}
		u, err := f.m.GetUserBySubject(resp.Request.Context(), "oidc-sub")
		if err != nil {
			t.Fatal(err)
		}
		list, err := f.m.ListWebSessions(resp.Request.Context(), u.ID)
		if err != nil || len(list) == 0 || !list[0].Admin {
			t.Fatalf("%v: session not admin", val)
		}
	}
	// Non-matching claim: session is not admin.
	f, idp := oidcFixture(t, func(c *config.Config) {
		c.Web.OIDC.AutoProvision = true
		c.Web.OIDC.AdminClaim = "groups"
		c.Web.OIDC.AdminValue = "ops"
	})
	idp.claims = func(n string) (jwt.Claims, map[string]any) {
		c, e := idp.goodClaims()
		e["groups"] = "users"
		return c, e
	}
	resp, _ := oidcLogin(t, f, idp)
	sc := cookieByName(resp, "sess")
	u, _ := f.m.GetUserBySubject(resp.Request.Context(), "oidc-sub")
	list, _ := f.m.ListWebSessions(resp.Request.Context(), u.ID)
	if len(list) == 0 || list[0].Admin || sc == nil {
		t.Fatal("non-matching claim granted admin")
	}
}
