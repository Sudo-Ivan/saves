// SPDX-License-Identifier: 0BSD

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// OIDCAuthenticator validates issuer JWTs with discovery JWKS.
type OIDCAuthenticator struct {
	cfg   OIDCConfig
	m     meta.Store
	hc    *http.Client
	clock func() time.Time

	mu         sync.Mutex
	jwks       *jose.JSONWebKeySet
	jwksURL    string
	fetchedAt  time.Time
	minRefresh time.Duration
}

// NewOIDC builds the authenticator, fetching discovery lazily.
func NewOIDC(m meta.Store, cfg OIDCConfig) (*OIDCAuthenticator, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("auth: oidc issuer required")
	}
	a := &OIDCAuthenticator{cfg: cfg, m: m, clock: time.Now, minRefresh: 60 * time.Second}
	a.hc = cfg.HTTPClient
	if a.hc == nil {
		a.hc = &http.Client{Transport: netx.NewTransport(), Timeout: 10 * time.Second}
	}
	for _, alg := range cfg.Algs {
		switch jose.SignatureAlgorithm(alg) {
		case jose.RS256, jose.RS384, jose.ES256, jose.EdDSA:
		default:
			return nil, fmt.Errorf("auth: oidc alg %q not allowed", alg)
		}
	}
	return a, nil
}

// SetClock injects a clock for tests.
func (a *OIDCAuthenticator) SetClock(c func() time.Time) { a.clock = c }

func (a *OIDCAuthenticator) getJSON(ctx context.Context, u string, max int64, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: oidc fetch %s: %s", u, resp.Status)
	}
	return json.NewDecoder(http.MaxBytesReader(nil, resp.Body, max)).Decode(v)
}

func (a *OIDCAuthenticator) discover(ctx context.Context) error {
	u := strings.TrimSuffix(a.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := a.getJSON(ctx, u, 1<<20, &doc); err != nil {
		return err
	}
	if doc.JWKSURI == "" {
		return errors.New("auth: oidc discovery missing jwks_uri")
	}
	if _, err := url.Parse(doc.JWKSURI); err != nil {
		return fmt.Errorf("auth: bad jwks_uri: %w", err)
	}
	a.jwksURL = doc.JWKSURI
	return a.refreshJWKS(ctx)
}

func (a *OIDCAuthenticator) refreshJWKS(ctx context.Context) error {
	var ks jose.JSONWebKeySet
	if err := a.getJSON(ctx, a.jwksURL, 4<<20, &ks); err != nil {
		return err
	}
	a.jwks = &ks
	a.fetchedAt = a.clock()
	return nil
}

// keys returns the cached set, refreshing when kid is unknown.
func (a *OIDCAuthenticator) keys(ctx context.Context, kid string) (*jose.JSONWebKeySet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.jwks == nil {
		if err := a.discover(ctx); err != nil {
			return nil, err
		}
	}
	for _, k := range a.jwks.Keys {
		if k.KeyID == kid || kid == "" {
			return a.jwks, nil
		}
	}
	if a.clock().Sub(a.fetchedAt) < a.minRefresh {
		return nil, errors.New("auth: unknown key id")
	}
	if err := a.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	return a.jwks, nil
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
	ks, err := a.keys(ctx, hdr.KeyID)
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
