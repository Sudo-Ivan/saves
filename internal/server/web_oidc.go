// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
)

// webOIDC holds the provider state for the code flow.
type webOIDC struct {
	prov   *auth.OIDCProvider
	client *http.Client
}

// oidcFlow is the sealed cookie payload.
type oidcFlow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"next"`
	Expires  int64  `json:"e"`
}

func (s *Server) oidcIssuer() string {
	if s.Cfg.Web.OIDC.Issuer != "" {
		return s.Cfg.Web.OIDC.Issuer
	}
	return s.Cfg.Auth.OIDC.Issuer
}

// provider lazily builds the shared OIDC provider; failures are
// retried on the next call.
func (s *Server) provider() (*webOIDC, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.oidc != nil {
		return s.oidc, nil
	}
	hc := &http.Client{Transport: netx.NewTransport(), Timeout: 10 * time.Second}
	p, err := auth.NewOIDCProvider(s.oidcIssuer(), s.Cfg.Auth.OIDC.Algs, hc)
	if err != nil {
		return nil, err
	}
	p.SetClock(s.Clock)
	s.oidc = &webOIDC{prov: p, client: hc}
	return s.oidc, nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// whOIDCStart begins the code flow: seal state, nonce, verifier and the
// next path into a short lived cookie, then redirect.
func (s *Server) whOIDCStart(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !s.Cfg.Web.OIDC.Enabled {
		wv.errorPage(404)
		return
	}
	wo, err := s.provider()
	if err != nil {
		s.Log.Warn("web oidc", "err", err)
		wv.errorPage(500)
		return
	}
	doc, err := wo.prov.Discover(r.Context())
	if err != nil || doc.Authorization == "" || doc.Token == "" {
		s.Log.Warn("web oidc discovery", "err", err)
		wv.errorPage(500)
		return
	}
	rnd := func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return b64url(b)
	}
	fl := oidcFlow{
		State: rnd(), Nonce: rnd(), Verifier: rnd(),
		Next:    safeNext(r.URL.Query().Get("next")),
		Expires: s.Clock().Add(10 * time.Minute).Unix(),
	}
	raw, _ := json.Marshal(fl)
	sealed, err := auth.Seal(wv.sessKey(), auth.SealOIDCCookie, []byte("oidc"), raw)
	if err != nil {
		wv.errorPage(500)
		return
	}
	wv.setCookie(oidcCookie, b64url(sealed), 600, false)
	ch := sha256.Sum256([]byte(fl.Verifier))
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.Cfg.Web.OIDC.ClientID)
	q.Set("redirect_uri", strings.TrimSuffix(s.Cfg.Web.PublicURL, "/")+"/auth/oidc/callback")
	q.Set("scope", s.Cfg.Web.OIDC.Scopes)
	q.Set("state", fl.State)
	q.Set("nonce", fl.Nonce)
	q.Set("code_challenge", b64url(ch[:]))
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, doc.Authorization+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) whOIDCCallback(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !s.Cfg.Web.OIDC.Enabled {
		wv.errorPage(404)
		return
	}
	fail := func(reason string, err error) {
		s.Log.Warn("web oidc login failed", "reason", reason, "err", err, "ip", s.clientIP(r))
		s.Met.WebLogin("failure")
		wv.render("login", 200, struct {
			Error, OIDCLabel                    string
			SignedOut, Password, OIDC, Register bool
			Next                                string
		}{Error: "Sign in failed.", OIDC: true, OIDCLabel: s.Cfg.Web.OIDC.Label,
			Password: s.Cfg.Web.PasswordLogin,
			Register: s.Reg != nil && s.Reg.Mode != auth.RegClosed, Next: "/account"})
	}
	raw := wv.readCookie(oidcCookie)
	// Single use: clear the cookie regardless of outcome.
	wv.setCookie(oidcCookie, "", -1, false)
	if raw == "" {
		fail("no_state", nil)
		return
	}
	ct, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		fail("bad_state", err)
		return
	}
	pt, err := auth.Open(wv.sessKey(), auth.SealOIDCCookie, []byte("oidc"), ct)
	if err != nil {
		fail("bad_state", err)
		return
	}
	var fl oidcFlow
	if err := json.Unmarshal(pt, &fl); err != nil {
		fail("bad_state", err)
		return
	}
	if s.Clock().Unix() > fl.Expires {
		fail("expired_state", nil)
		return
	}
	got := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(got), []byte(fl.State)) != 1 {
		fail("state_mismatch", nil)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		fail("no_code", errors.New(r.URL.Query().Get("error")))
		return
	}
	wo, err := s.provider()
	if err != nil {
		fail("provider", err)
		return
	}
	doc, err := wo.prov.Discover(r.Context())
	if err != nil {
		fail("discovery", err)
		return
	}
	// https endpoints only, http allowed for loopback hosts like the
	// issuer rule in config.
	for _, e := range []string{doc.Token, doc.JWKSURI, doc.Authorization} {
		u, perr := url.Parse(e)
		if perr != nil || (u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
			fail("insecure_endpoint", fmt.Errorf("%s", e))
			return
		}
	}
	idToken, err := s.exchangeCode(r.Context(), wo, doc.Token, code, fl.Verifier)
	if err != nil {
		fail("token_exchange", err)
		return
	}
	claims, all, err := wo.prov.VerifyIDToken(r.Context(), idToken,
		s.Cfg.Web.OIDC.ClientID, fl.Nonce, s.Cfg.Auth.OIDC.ClockSkew.Duration())
	if err != nil {
		fail("id_token", err)
		return
	}
	u, err := s.Meta.GetUserBySubject(r.Context(), claims.Subject)
	if errors.Is(err, meta.ErrNotFound) {
		if !s.Cfg.Web.OIDC.AutoProvision {
			fail("unknown_user", nil)
			return
		}
		u, _, err = s.Meta.UpsertUser(r.Context(), claims.Subject, s.Cfg.Quota.DefaultTier)
	}
	if err != nil {
		fail("user", err)
		return
	}
	if u.Disabled || u.DeletedAt != nil {
		fail("disabled", nil)
		return
	}
	admin := claimContains(all[s.Cfg.Web.OIDC.AdminClaim], s.Cfg.Web.OIDC.AdminValue)
	if err := wv.createSession(u.ID, meta.SessionFull, meta.SessionMethodOIDC,
		admin, s.Cfg.Web.Session.Absolute.Duration()); err != nil {
		s.Log.Error("web session create", "err", err)
		wv.errorPage(500)
		return
	}
	s.Met.WebLogin("oidc")
	s.Log.Info("web login", "user", u.ID, "method", "oidc", "ip", s.clientIP(r))
	http.Redirect(w, r, wv.web.link+strings.TrimPrefix(fl.Next, "/"), http.StatusSeeOther)
}

// exchangeCode swaps the authorization code for tokens.
func (s *Server) exchangeCode(ctx context.Context, wo *webOIDC, endpoint, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {strings.TrimSuffix(s.Cfg.Web.PublicURL, "/") + "/auth/oidc/callback"},
		"client_id":     {s.Cfg.Web.OIDC.ClientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if sec := s.Cfg.Web.OIDC.ClientSecret; sec != "" {
		req.SetBasicAuth(url.QueryEscape(s.Cfg.Web.OIDC.ClientID), url.QueryEscape(sec))
	}
	resp, err := wo.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint: %s", resp.Status)
	}
	var out struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.IDToken == "" {
		return "", errors.New("token response missing id_token")
	}
	return out.IDToken, nil
}

// claimContains reports whether the claim (string or array) carries
// the wanted value.
func claimContains(v any, want string) bool {
	if want == "" {
		return false
	}
	switch t := v.(type) {
	case string:
		return t == want
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, x := range t {
			if x == want {
				return true
			}
		}
	}
	return false
}

// loopbackHost reports whether host is a loopback name or address.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
