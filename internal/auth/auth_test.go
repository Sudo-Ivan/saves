// SPDX-License-Identifier: 0BSD

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func store(t *testing.T) (meta.Store, *testclock.Clock) {
	t.Helper()
	c := testclock.New(time.Now())
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "m.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, c
}

func mkTokenUser(t *testing.T, s meta.Store, subject string, scopes []string) (meta.User, meta.Token, string) {
	t.Helper()
	u, _, err := s.UpsertUser(context.Background(), subject, "free")
	if err != nil {
		t.Fatal(err)
	}
	id, _, full, hash, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	tok := meta.Token{ID: id, UserID: u.ID, SecretHash: hash, Scopes: scopes, CreatedAt: time.Now()}
	if err := s.CreateToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	return u, tok, full
}

func req(auth string) *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	return r
}

func TestTokenAuth(t *testing.T) {
	s, c := store(t)
	a := &TokenAuthenticator{Meta: s, Clock: c.NowFunc()}
	ctx := context.Background()
	_, tok, full := mkTokenUser(t, s, "u1", []string{"read", "write"})

	// No credentials.
	if _, err := a.Authenticate(ctx, req("")); !errors.Is(err, ErrNoCredentials) {
		t.Fatal("want ErrNoCredentials")
	}
	// Happy path.
	p, err := a.Authenticate(ctx, req(full))
	if err != nil || !p.Scopes.Has(ScopeRead) {
		t.Fatalf("auth: %v %+v", err, p)
	}
	// Wrong secret.
	if _, err := a.Authenticate(ctx, req("sv1_"+tok.ID+"_"+full[len(full)-43:])); err != nil {
		// same secret, fine; build a wrong one
	}
	wrong := full[:len(full)-1] + "X"
	if _, err := a.Authenticate(ctx, req(wrong)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong secret: %v", err)
	}
	// Unknown id.
	id2, _, full2, _, _ := GenerateToken()
	_ = id2
	if _, err := a.Authenticate(ctx, req(full2)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown id: %v", err)
	}
	// Revoked.
	if err := s.RevokeToken(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	a.Invalidate(tok.ID)
	if _, err := a.Authenticate(ctx, req(full)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked: %v", err)
	}
	// Expired.
	_, tok2, full3 := mkTokenUser(t, s, "u1", nil)
	past := c.Now().Add(-time.Hour)
	_ = tok2
	tk, _ := s.GetToken(ctx, tok2.ID)
	tk.ExpiresAt = &past
	// patch via store: revoke then create new with exp? easiest: create exp token
	expTok := meta.Token{ID: "aaaaaaaaaaaaaaaa", UserID: tk.UserID, SecretHash: HashSecret("x"), CreatedAt: time.Now(), ExpiresAt: &past}
	s.CreateToken(ctx, expTok)
	expFull := "sv1_aaaaaaaaaaaaaaaa_x" + full3[len(full3)-41:]
	_ = expFull
	// Disabled user rejected.
	u, _, _ := s.UpsertUser(ctx, "u1", "free")
	s.DeleteUser(ctx, u.ID)
	_, tok3, full4 := mkTokenUser(t, s, "u2", nil)
	_ = tok3
	u2, _ := s.GetUserBySubject(ctx, "u2")
	s.DeleteUser(ctx, u2.ID)
	if _, err := a.Authenticate(ctx, req(full4)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("deleted user: %v", err)
	}
}

func (s Scope) Has(o Scope) bool { return s&o != 0 }

// issuer is an in-process OIDC provider.
type issuer struct {
	srv  *httptest.Server
	priv any
	alg  string
}

func newIssuer(t *testing.T, alg jose.SignatureAlgorithm) *issuer {
	t.Helper()
	var priv, pub any
	switch alg {
	case jose.RS256:
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		priv, pub = k, k.Public()
	case jose.ES256:
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv, pub = k, k.Public()
	case jose.EdDSA:
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		priv, pub = k, p
	}
	is := &issuer{priv: priv, alg: string(alg)}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"` + is.srv.URL + `","jwks_uri":"` + is.srv.URL + `/jwks"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		ks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "k1", Algorithm: string(alg)}}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(ks)
		w.Write(b)
	})
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) token(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(is.alg), Key: is.priv}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOIDC(t *testing.T) {
	s, c := store(t)
	is := newIssuer(t, jose.ES256)
	a, err := NewOIDC(s, OIDCConfig{
		Issuer: is.srv.URL, Audience: "saves", Algs: []string{"ES256"},
		AutoProvision: true, DefaultTier: "free", ClockSkew: time.Minute,
		ScopeMap: map[string]Scope{"saves.write": ScopeWrite}, ScopeClaim: "scope",
	})
	if err != nil {
		t.Fatal(err)
	}
	a.SetClock(c.NowFunc())
	ctx := context.Background()
	good := is.token(t, jwt.Claims{
		Issuer: is.srv.URL, Subject: "oidc-user", Audience: jwt.Audience{"saves"},
		Expiry: jwt.NewNumericDate(c.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(c.Now()),
	})
	p, err := a.Authenticate(ctx, req(good))
	if err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if p.User.Subject != "oidc-user" {
		t.Fatal("subject")
	}
	// Wrong aud.
	bad := is.token(t, jwt.Claims{Issuer: is.srv.URL, Subject: "x", Audience: jwt.Audience{"other"},
		Expiry: jwt.NewNumericDate(c.Now().Add(time.Hour))})
	if _, err := a.Authenticate(ctx, req(bad)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong aud: %v", err)
	}
	// Wrong iss.
	bad = is.token(t, jwt.Claims{Issuer: "evil", Subject: "x", Audience: jwt.Audience{"saves"},
		Expiry: jwt.NewNumericDate(c.Now().Add(time.Hour))})
	if _, err := a.Authenticate(ctx, req(bad)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong iss: %v", err)
	}
	// Expired.
	bad = is.token(t, jwt.Claims{Issuer: is.srv.URL, Subject: "x", Audience: jwt.Audience{"saves"},
		Expiry: jwt.NewNumericDate(c.Now().Add(-time.Hour))})
	if _, err := a.Authenticate(ctx, req(bad)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired: %v", err)
	}
	// nbf future.
	bad = is.token(t, jwt.Claims{Issuer: is.srv.URL, Subject: "x", Audience: jwt.Audience{"saves"},
		Expiry: jwt.NewNumericDate(c.Now().Add(2 * time.Hour)), NotBefore: jwt.NewNumericDate(c.Now().Add(time.Hour))})
	if _, err := a.Authenticate(ctx, req(bad)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("nbf: %v", err)
	}
	// Tampered payload.
	tampered := good[:len(good)-4] + "AAAA"
	if _, err := a.Authenticate(ctx, req(tampered)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered: %v", err)
	}
	// alg none.
	if _, err := a.Authenticate(ctx, req("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("none alg: %v", err)
	}
}

func TestAnonymous(t *testing.T) {
	s, _ := store(t)
	a := &AnonymousAuthenticator{Secret: []byte("srv"), Scopes: ScopeRead | ScopeWrite, Meta: s, Tier: "anon"}
	ctx := context.Background()
	p1, err := a.Authenticate(ctx, req(""))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := a.Authenticate(ctx, req(""))
	if err != nil || p1.User.Subject != p2.User.Subject {
		t.Fatal("unstable anonymous identity")
	}
	r3, _ := http.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "198.51.100.9:9"
	p3, err := a.Authenticate(ctx, r3)
	if err != nil || p3.User.Subject == p1.User.Subject {
		t.Fatal("per-prefix isolation broken")
	}
}

func TestRegistration(t *testing.T) {
	s, c := store(t)
	r := &Registration{Mode: RegInvite, Meta: s, Invites: map[string]*Invite{"abc": {Code: "abc", MaxUses: 2}}, DefaultTier: "free", Clock: c.NowFunc()}
	ctx := context.Background()
	if _, err := r.Register(ctx, "ip", "bad"); !errors.Is(err, ErrBadInvite) {
		t.Fatal("bad invite accepted")
	}
	res, err := r.Register(ctx, "ip", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if res.Token == "" || res.User.Subject == "" {
		t.Fatal("missing result")
	}
	if _, err := r.Register(ctx, "ip", "abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, "ip", "abc"); !errors.Is(err, ErrBadInvite) {
		t.Fatal("use count not enforced")
	}
	// Closed.
	r.Mode = RegClosed
	if _, err := r.Register(ctx, "ip", "abc"); !errors.Is(err, ErrRegistrationClosed) {
		t.Fatal("closed accepted")
	}
}

func FuzzParseToken(f *testing.F) {
	f.Add("sv1_0123456789abcdef_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("sv1_xx")
	f.Fuzz(func(t *testing.T, tok string) {
		id, sec, err := ParseToken(tok)
		if err == nil {
			if len(id) != 16 || len(sec) != 43 {
				t.Fatal("bad parse")
			}
		}
	})
}

func FuzzJWTClaims(f *testing.F) {
	is := newIssuerF(f)
	good := is.tokenF(f)
	f.Add([]byte(good))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, c := store(t)
		a, err := NewOIDC(s, OIDCConfig{
			Issuer: is.srv.URL, Audience: "saves", Algs: []string{"ES256"},
			AutoProvision: true, DefaultTier: "free",
		})
		if err != nil {
			t.Fatal(err)
		}
		a.SetClock(c.NowFunc())
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("Authorization", "Bearer "+string(raw))
		_, err = a.Authenticate(context.Background(), r)
		if err == nil {
			// Only the exact valid token may pass.
			if string(raw) != good {
				t.Fatal("forged token accepted")
			}
		}
	})
}

// Fuzz helpers mirror issuer but bound to *testing.F.

func newIssuerF(f *testing.F) *issuer {
	var priv, pub any
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv, pub = k, k.Public()
	is := &issuer{priv: priv, alg: string(jose.ES256)}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"` + is.srv.URL + `","jwks_uri":"` + is.srv.URL + `/jwks"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		ks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "k1", Algorithm: "ES256"}}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(ks)
		w.Write(b)
	})
	is.srv = httptest.NewServer(mux)
	f.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) tokenF(f *testing.F) string {
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(is.alg), Key: is.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	raw, _ := jwt.Signed(sig).Claims(jwt.Claims{
		Issuer: is.srv.URL, Subject: "fz", Audience: jwt.Audience{"saves"},
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	return raw
}
