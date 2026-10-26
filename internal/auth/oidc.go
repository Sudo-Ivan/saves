// SPDX-License-Identifier: 0BSD

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// OIDCConfig configures the OIDC authenticator.
type OIDCConfig struct {
	Issuer        string
	Audience      string
	Algs          []string // e.g. RS256 ES256 EdDSA
	AutoProvision bool
	DefaultTier   string
	ClockSkew     time.Duration
	ScopeClaim    string           // claim with space separated scopes, default "scope"
	ScopeMap      map[string]Scope // oidc scope -> api scope
	DefaultScopes Scope
	HTTPClient    *http.Client
}

// OIDCDiscovery is the subset of the discovery document we consume.
type OIDCDiscovery struct {
	Issuer        string `json:"issuer"`
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// OIDCProvider wraps discovery and JWKS fetching so the bearer
// authenticator and the web login flow share one implementation.
type OIDCProvider struct {
	Issuer     string
	Algs       []string
	HTTPClient *http.Client
	clock      func() time.Time
	minRefresh time.Duration

	mu        sync.Mutex
	doc       *OIDCDiscovery
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
}

// NewOIDCProvider builds a provider; discovery is lazy.
func NewOIDCProvider(issuer string, algs []string, hc *http.Client) (*OIDCProvider, error) {
	if issuer == "" {
		return nil, errors.New("auth: oidc issuer required")
	}
	if hc == nil {
		hc = &http.Client{Transport: netx.NewTransport(), Timeout: 10 * time.Second}
	}
	p := &OIDCProvider{Issuer: issuer, Algs: algs, HTTPClient: hc,
		clock: time.Now, minRefresh: 60 * time.Second}
	for _, alg := range algs {
		switch jose.SignatureAlgorithm(alg) {
		case jose.RS256, jose.RS384, jose.ES256, jose.EdDSA:
		default:
			return nil, fmt.Errorf("auth: oidc alg %q not allowed", alg)
		}
	}
	return p, nil
}

// SetClock injects a clock for tests.
func (p *OIDCProvider) SetClock(c func() time.Time) { p.clock = c }

func (p *OIDCProvider) getJSON(ctx context.Context, u string, max int64, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: oidc fetch %s: %s", u, resp.Status)
	}
	return json.NewDecoder(http.MaxBytesReader(nil, resp.Body, max)).Decode(v)
}

// Discover returns the cached discovery document. The doc issuer must
// equal the configured issuer.
func (p *OIDCProvider) Discover(ctx context.Context) (*OIDCDiscovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discover(ctx)
}

// discover is the unlocked worker; callers hold p.mu.
func (p *OIDCProvider) discover(ctx context.Context) (*OIDCDiscovery, error) {
	if p.doc != nil {
		return p.doc, nil
	}
	u := strings.TrimSuffix(p.Issuer, "/") + "/.well-known/openid-configuration"
	var doc OIDCDiscovery
	if err := p.getJSON(ctx, u, 1<<20, &doc); err != nil {
		return nil, err
	}
	if doc.Issuer != strings.TrimSuffix(p.Issuer, "/") && doc.Issuer != p.Issuer {
		return nil, errors.New("auth: oidc discovery issuer mismatch")
	}
	if doc.JWKSURI == "" {
		return nil, errors.New("auth: oidc discovery missing jwks_uri")
	}
	p.doc = &doc
	return &doc, nil
}

// Keys returns the cached key set, refreshing when kid is unknown.
func (p *OIDCProvider) Keys(ctx context.Context, kid string) (*jose.JSONWebKeySet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.doc == nil {
		if _, err := p.discover(ctx); err != nil {
			return nil, err
		}
	}
	if p.jwks == nil {
		if err := p.refreshJWKS(ctx); err != nil {
			return nil, err
		}
	}
	for _, k := range p.jwks.Keys {
		if k.KeyID == kid || kid == "" {
			return p.jwks, nil
		}
	}
	if p.clock().Sub(p.fetchedAt) < p.minRefresh {
		return nil, errors.New("auth: unknown key id")
	}
	if err := p.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	return p.jwks, nil
}

func (p *OIDCProvider) refreshJWKS(ctx context.Context) error {
	var ks jose.JSONWebKeySet
	if err := p.getJSON(ctx, p.doc.JWKSURI, 4<<20, &ks); err != nil {
		return err
	}
	p.jwks = &ks
	p.fetchedAt = p.clock()
	return nil
}

// VerifyIDToken validates signature, issuer, audience, expiry, and
// nonce of a raw id_token.
func (p *OIDCProvider) VerifyIDToken(ctx context.Context, raw, clientID, nonce string, skew time.Duration) (jwt.Claims, map[string]any, error) {
	var claims jwt.Claims
	var all map[string]any
	tok, err := jwt.ParseSigned(raw, algs(p.Algs))
	if err != nil {
		return claims, nil, ErrUnauthorized
	}
	var hdr jose.Header
	if len(tok.Headers) > 0 {
		hdr = tok.Headers[0]
	}
	ks, err := p.Keys(ctx, hdr.KeyID)
	if err != nil {
		return claims, nil, err
	}
	verified := false
	for _, k := range ks.Keys {
		if hdr.KeyID != "" && k.KeyID != hdr.KeyID {
			continue
		}
		if err := tok.Claims(k, &claims, &all); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return claims, nil, ErrUnauthorized
	}
	exp := jwt.Expected{
		Issuer:      p.Issuer,
		AnyAudience: jwt.Audience{clientID},
		Time:        p.clock(),
	}
	if err := claims.ValidateWithLeeway(exp, skew); err != nil {
		return claims, nil, ErrUnauthorized
	}
	if len(claims.Audience) > 1 {
		if azp, _ := all["azp"].(string); azp != clientID {
			return claims, nil, ErrUnauthorized
		}
	}
	if claims.Subject == "" {
		return claims, nil, ErrUnauthorized
	}
	if n, _ := all["nonce"].(string); n != nonce {
		return claims, nil, ErrUnauthorized
	}
	return claims, all, nil
}

// OIDCAuthenticator validates issuer JWTs with discovery JWKS.
type OIDCAuthenticator struct {
	cfg   OIDCConfig
	m     meta.Store
	hc    *http.Client
	clock func() time.Time
	prov  *OIDCProvider
}

// NewOIDC builds the authenticator, fetching discovery lazily.
func NewOIDC(m meta.Store, cfg OIDCConfig) (*OIDCAuthenticator, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("auth: oidc issuer required")
	}
	prov, err := NewOIDCProvider(cfg.Issuer, cfg.Algs, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	a := &OIDCAuthenticator{cfg: cfg, m: m, clock: time.Now, hc: cfg.HTTPClient, prov: prov}
	if a.hc == nil {
		a.hc = prov.HTTPClient
	}
	return a, nil
}

// SetClock injects a clock for tests.
func (a *OIDCAuthenticator) SetClock(c func() time.Time) {
	a.clock = c
	a.prov.SetClock(c)
}

// Authenticate implements Authenticator.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, r *http.Request) (Principal, error) {
	raw, ok := bearer(r)
	if !ok || strings.HasPrefix(raw, tokenPrefix) {
		return Principal{}, ErrNoCredentials
	}
	tok, err := jwt.ParseSigned(raw, algs(a.cfg.Algs))
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	var hdr jose.Header
	if len(tok.Headers) > 0 {
		hdr = tok.Headers[0]
	}
	ks, err := a.prov.Keys(ctx, hdr.KeyID)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	var claims jwt.Claims
	var all map[string]any
	verified := false
	for _, k := range ks.Keys {
		if hdr.KeyID != "" && k.KeyID != hdr.KeyID {
			continue
		}
		if err := tok.Claims(k, &claims, &all); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return Principal{}, ErrUnauthorized
	}
	exp := jwt.Expected{
		Issuer:      a.cfg.Issuer,
		AnyAudience: jwt.Audience{a.cfg.Audience},
		Time:        a.clock(),
	}
	if err := claims.ValidateWithLeeway(exp, a.cfg.ClockSkew); err != nil {
		return Principal{}, ErrUnauthorized
	}
	if claims.Subject == "" {
		return Principal{}, ErrUnauthorized
	}
	sc := a.cfg.DefaultScopes
	if claim, _ := all[a.cfg.ScopeClaim].(string); claim != "" {
		for _, w := range strings.Fields(claim) {
			if mapped, ok := a.cfg.ScopeMap[w]; ok {
				sc |= mapped
			}
		}
	}
	u, created, err := a.m.UpsertUser(ctx, claims.Subject, a.cfg.DefaultTier)
	if err != nil {
		return Principal{}, err
	}
	if !a.cfg.AutoProvision && created {
		return Principal{}, ErrUnauthorized
	}
	if u.Disabled || u.DeletedAt != nil {
		return Principal{}, ErrUnauthorized
	}
	return Principal{User: u, Scopes: sc, Admin: sc&ScopeAdmin != 0}, nil
}

func algs(in []string) []jose.SignatureAlgorithm {
	if len(in) == 0 {
		in = []string{"RS256", "ES256", "EdDSA"}
	}
	out := make([]jose.SignatureAlgorithm, 0, len(in))
	for _, a := range in {
		out = append(out, jose.SignatureAlgorithm(a))
	}
	return out
}
