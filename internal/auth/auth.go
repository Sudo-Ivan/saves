// SPDX-License-Identifier: 0BSD

// Package auth turns request credentials into principals. It provides
// a token authenticator (sv1 id secret), an OIDC authenticator backed
// by go-jose, a trusted proxy header authenticator, and an anonymous
// authenticator, plus a Chain combinator and the registration service.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/ratelimit"
)

// Principal is the authenticated identity.
type Principal struct {
	User   meta.User
	Scopes Scope
	// Apps is the token app allowlist; nil means all apps.
	Apps      []string
	TokenID   string
	Anonymous bool
	Admin     bool
}

// Scope is a bitset of capabilities.
type Scope uint8

const (
	ScopeRead  Scope = 1 << 0
	ScopeWrite Scope = 1 << 1
	ScopeAdmin Scope = 1 << 2
)

// ParseScopes parses a comma separated scope list.
func ParseScopes(s string) (Scope, error) {
	var sc Scope
	for _, p := range strings.Split(s, ",") {
		switch strings.TrimSpace(p) {
		case "":
		case "read":
			sc |= ScopeRead
		case "write":
			sc |= ScopeWrite
		case "admin":
			sc |= ScopeAdmin
		default:
			return 0, fmt.Errorf("auth: unknown scope %q", p)
		}
	}
	return sc, nil
}

// String formats the scope set.
func (s Scope) String() string {
	var p []string
	if s&ScopeRead != 0 {
		p = append(p, "read")
	}
	if s&ScopeWrite != 0 {
		p = append(p, "write")
	}
	if s&ScopeAdmin != 0 {
		p = append(p, "admin")
	}
	return strings.Join(p, ",")
}

var (
	ErrNoCredentials = errors.New("auth: no credentials")
	ErrUnauthorized  = errors.New("auth: invalid credentials")
	ErrForbidden     = errors.New("auth: insufficient scope")
	ErrRateLimited   = errors.New("auth: too many failures")
)

// Authenticator extracts a principal from a request.
type Authenticator interface {
	// Authenticate returns ErrNoCredentials when the request carries no
	// credential of this authenticator's kind, ErrUnauthorized when the
	// credential is present but rejected.
	Authenticate(ctx context.Context, r *http.Request) (Principal, error)
}

// Chain tries each authenticator in order.
type Chain []Authenticator

// Authenticate implements Authenticator.
func (c Chain) Authenticate(ctx context.Context, r *http.Request) (Principal, error) {
	var last error = ErrNoCredentials
	for _, a := range c {
		p, err := a.Authenticate(ctx, r)
		switch {
		case err == nil:
			return p, nil
		case errors.Is(err, ErrNoCredentials):
			continue
		default:
			last = err
		}
	}
	return Principal{}, last
}

// bearer extracts the Bearer token.
func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	return strings.TrimSpace(h[7:]), true
}

// sv1 token format: sv1_<16 hex id>_<43 char base64url secret>.
const tokenPrefix = "sv1_"

// GenerateToken creates a new opaque token string.
func GenerateToken() (id, secret, full string, hash [32]byte, err error) {
	var ib [8]byte
	var sb [32]byte
	if _, err = rand.Read(ib[:]); err != nil {
		return
	}
	if _, err = rand.Read(sb[:]); err != nil {
		return
	}
	id = hex.EncodeToString(ib[:])
	secret = base64.RawURLEncoding.EncodeToString(sb[:])
	full = tokenPrefix + id + "_" + secret
	hash = HashSecret(secret)
	return
}

// HashSecret is the stored token hash.
func HashSecret(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

// ParseToken splits a sv1 token into id and secret.
func ParseToken(tok string) (id, secret string, err error) {
	if !strings.HasPrefix(tok, tokenPrefix) {
		return "", "", ErrUnauthorized
	}
	rest := tok[len(tokenPrefix):]
	i := strings.IndexByte(rest, '_')
	if i != 16 {
		return "", "", ErrUnauthorized
	}
	id = rest[:16]
	if _, err := hex.DecodeString(id); err != nil {
		return "", "", ErrUnauthorized
	}
	secret = rest[17:]
	if len(secret) != 43 {
		return "", "", ErrUnauthorized
	}
	if _, err := base64.RawURLEncoding.DecodeString(secret); err != nil {
		return "", "", ErrUnauthorized
	}
	return id, secret, nil
}

// dummySecret hashes like a real secret so unknown ids cost the same.
var dummyHash = sha256.Sum256([]byte("auth-dummy-secret"))

// TokenAuthenticator validates sv1 tokens against the meta store.
type TokenAuthenticator struct {
	Meta     meta.Store
	Clock    func() time.Time
	TouchTTL time.Duration
	// CacheTTL bounds the validation cache; 0 uses a 10s default.
	CacheTTL time.Duration
	// FailLimiter is a per-IP failed-auth token bucket.
	FailLimiter *ratelimit.Limiter

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// cacheEntry is one cached token validation.
type cacheEntry struct {
	hash    [32]byte
	user    meta.User
	scopes  Scope
	apps    []string
	expires time.Time
}

func (a *TokenAuthenticator) now() time.Time {
	if a.Clock == nil {
		return time.Now()
	}
	return a.Clock()
}

func (a *TokenAuthenticator) cached(id string) (*cacheEntry, bool) {
	if a.cache == nil {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.cache[id]
	if !ok || e.expires.Before(a.now()) {
		if ok {
			delete(a.cache, id)
		}
		return nil, false
	}
	return &e, true
}

func (a *TokenAuthenticator) storeCache(id string, e cacheEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache == nil {
		a.cache = map[string]cacheEntry{}
	}
	if len(a.cache) > 4096 {
		// Crude bound: drop everything, refill lazily.
		a.cache = map[string]cacheEntry{}
	}
	a.cache[id] = e
}

// Invalidate drops the cache entry for id, e.g. after local revocation.
func (a *TokenAuthenticator) Invalidate(id string) {
	a.mu.Lock()
	if a.cache != nil {
		delete(a.cache, id)
	}
	a.mu.Unlock()
}

// Authenticate implements Authenticator.
func (a *TokenAuthenticator) Authenticate(ctx context.Context, r *http.Request) (Principal, error) {
	tok, ok := bearer(r)
	if !ok {
		return Principal{}, ErrNoCredentials
	}
	ip := netx.IPPrefix(netx.ClientIP(r, nil))
	fail := func(err error) (Principal, error) {
		if a.FailLimiter != nil {
			if ok, _ := a.FailLimiter.Allow(ip, 1); !ok {
				return Principal{}, ErrRateLimited
			}
		}
		return Principal{}, err
	}
	id, secret, err := ParseToken(tok)
	if err != nil {
		return fail(err)
	}
	got := HashSecret(secret)
	now := a.now()
	if ce, ok := a.cached(id); ok {
		if !hmac.Equal(got[:], ce.hash[:]) {
			return fail(ErrUnauthorized)
		}
		return Principal{User: ce.user, Scopes: ce.scopes, Apps: ce.apps, TokenID: id,
			Admin: ce.scopes&ScopeAdmin != 0}, nil
	}
	t, err := a.Meta.GetToken(ctx, id)
	if err != nil {
		// Unknown id: compare against a dummy hash for equal work.
		_ = hmac.Equal(got[:], dummyHash[:])
		return fail(ErrUnauthorized)
	}
	if !hmac.Equal(got[:], t.SecretHash[:]) {
		return fail(ErrUnauthorized)
	}
	if t.RevokedAt != nil {
		return fail(ErrUnauthorized)
	}
	if t.ExpiresAt != nil && t.ExpiresAt.Before(now) {
		return fail(ErrUnauthorized)
	}
	u, err := a.Meta.GetUser(ctx, t.UserID)
	if err != nil {
		return fail(ErrUnauthorized)
	}
	if u.Disabled || u.DeletedAt != nil {
		return fail(ErrUnauthorized)
	}
	// Throttled last-used tracking, asynchronous to keep the hot path
	// off the single sqlite writer.
	if a.TouchTTL <= 0 || t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > a.TouchTTL {
		go func() { _ = a.Meta.TouchToken(context.Background(), id, now) }() // #nosec G118 -- detached write must outlive the request context
	}
	sc, _ := ParseScopes(strings.Join(t.Scopes, ","))
	p := Principal{User: u, Scopes: sc, Apps: t.Apps, TokenID: id, Admin: sc&ScopeAdmin != 0}
	ttl := a.CacheTTL
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	a.storeCache(id, cacheEntry{hash: t.SecretHash, user: u, scopes: sc, apps: t.Apps,
		expires: now.Add(ttl)})
	return p, nil
}

// ProxyAuthenticator trusts forwarded identity headers only when the
// direct peer is inside a trusted CIDR.
type ProxyAuthenticator struct {
	Trusted       []netip.Prefix
	Meta          meta.Store
	SubjectHdr    string // e.g. X-Forwarded-User
	AutoProvision bool
	DefaultTier   string
}

// Authenticate implements Authenticator.
func (a *ProxyAuthenticator) Authenticate(ctx context.Context, r *http.Request) (Principal, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return Principal{}, ErrNoCredentials
	}
	trusted := false
	for _, p := range a.Trusted {
		if p.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return Principal{}, ErrNoCredentials
	}
	h := a.SubjectHdr
	if h == "" {
		h = "X-Forwarded-User"
	}
	subject := strings.TrimSpace(r.Header.Get(h))
	if subject == "" {
		return Principal{}, ErrNoCredentials
	}
	u, created, err := a.Meta.UpsertUser(ctx, subject, a.DefaultTier)
	if err != nil {
		return Principal{}, err
	}
	if !a.AutoProvision && created {
		return Principal{}, ErrUnauthorized
	}
	if u.Disabled || u.DeletedAt != nil {
		return Principal{}, ErrUnauthorized
	}
	return Principal{User: u, Scopes: ScopeRead | ScopeWrite}, nil
}

// AnonymousAuthenticator assigns a stable HMAC identity per IP prefix.
type AnonymousAuthenticator struct {
	Secret  []byte
	Scopes  Scope
	Tier    string
	Meta    meta.Store
	Trusted []netip.Prefix
}

// Authenticate implements Authenticator.
func (a *AnonymousAuthenticator) Authenticate(ctx context.Context, r *http.Request) (Principal, error) {
	ip := netx.ClientIP(r, a.Trusted)
	mac := hmac.New(sha256.New, a.Secret)
	mac.Write([]byte(netx.IPPrefix(ip)))
	subject := "anon:" + hex.EncodeToString(mac.Sum(nil)[:16])
	u, _, err := a.Meta.UpsertUser(ctx, subject, a.Tier)
	if err != nil {
		return Principal{}, err
	}
	if u.Disabled || u.DeletedAt != nil {
		return Principal{}, ErrUnauthorized
	}
	return Principal{User: u, Scopes: a.Scopes, Anonymous: true}, nil
}
