// SPDX-License-Identifier: 0BSD

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func provFor(t *testing.T, is *issuer) *OIDCProvider {
	t.Helper()
	p, err := NewOIDCProvider(is.srv.URL, []string{"ES256", "RS256"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func goodClaims(is *issuer, c func() time.Time) jwt.Claims {
	return jwt.Claims{
		Issuer:   is.srv.URL,
		Subject:  "sub1",
		Audience: jwt.Audience{"saves"},
		IssuedAt: jwt.NewNumericDate(c()),
		Expiry:   jwt.NewNumericDate(c().Add(time.Hour)),
	}
}

// TestVerifyIDToken exercises the provider id_token rules.
func TestVerifyIDToken(t *testing.T) {
	is := newIssuer(t, jose.ES256)
	p := provFor(t, is)
	now := time.Now
	ctx := context.Background()

	sign := func(claims jwt.Claims, extra map[string]any) string {
		t.Helper()
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: is.priv},
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
	base := func() jwt.Claims { return goodClaims(is, now) }

	t.Run("good", func(t *testing.T) {
		raw := sign(base(), map[string]any{"nonce": "n1"})
		cl, _, err := p.VerifyIDToken(ctx, raw, "saves", "n1", time.Minute)
		if err != nil || cl.Subject != "sub1" {
			t.Fatalf("good token: %v", err)
		}
	})
	t.Run("aud list with azp", func(t *testing.T) {
		c := base()
		c.Audience = jwt.Audience{"saves", "other"}
		raw := sign(c, map[string]any{"nonce": "n1", "azp": "saves"})
		if _, _, err := p.VerifyIDToken(ctx, raw, "saves", "n1", time.Minute); err != nil {
			t.Fatalf("azp token: %v", err)
		}
	})
	cases := []struct {
		name  string
		raw   func() string
		nonce string
	}{
		{"wrong nonce", func() string { return sign(base(), map[string]any{"nonce": "n2"}) }, "n1"},
		{"missing nonce", func() string { return sign(base(), nil) }, "n1"},
		{"wrong audience", func() string {
			c := base()
			c.Audience = jwt.Audience{"not-saves"}
			return sign(c, map[string]any{"nonce": "n1"})
		}, "n1"},
		{"aud list no azp", func() string {
			c := base()
			c.Audience = jwt.Audience{"saves", "other"}
			return sign(c, map[string]any{"nonce": "n1"})
		}, "n1"},
		{"azp mismatch", func() string {
			c := base()
			c.Audience = jwt.Audience{"saves", "other"}
			return sign(c, map[string]any{"nonce": "n1", "azp": "other"})
		}, "n1"},
		{"wrong issuer", func() string {
			c := base()
			c.Issuer = "https://evil.example"
			return sign(c, map[string]any{"nonce": "n1"})
		}, "n1"},
		{"expired", func() string {
			c := base()
			c.Expiry = jwt.NewNumericDate(now().Add(-time.Hour))
			return sign(c, map[string]any{"nonce": "n1"})
		}, "n1"},
		{"nbf beyond skew", func() string {
			c := base()
			c.NotBefore = jwt.NewNumericDate(now().Add(time.Hour))
			return sign(c, map[string]any{"nonce": "n1"})
		}, "n1"},
		{"empty sub", func() string {
			c := base()
			c.Subject = ""
			return sign(c, map[string]any{"nonce": "n1"})
		}, "n1"},
		{"kid not in jwks", func() string {
			sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: is.priv},
				(&jose.SignerOptions{}).WithHeader("kid", "k9").WithType("JWT"))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := jwt.Signed(sig).Claims(base()).Claims(map[string]any{"nonce": "n1"}).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}, "n1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := p.VerifyIDToken(ctx, tc.raw(), "saves", tc.nonce, time.Minute); err == nil {
				t.Fatal("bad token accepted")
			}
		})
	}

	t.Run("unsigned", func(t *testing.T) {
		// alg none: header + claims + empty signature.
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		c := base()
		plB, _ := json.Marshal(map[string]any{
			"iss": c.Issuer, "sub": c.Subject, "aud": c.Audience,
			"iat": c.IssuedAt.Time().Unix(), "exp": c.Expiry.Time().Unix(),
			"nonce": "n1"})
		pl := base64.RawURLEncoding.EncodeToString(plB)
		raw := hdr + "." + pl + "."
		if _, _, err := p.VerifyIDToken(ctx, raw, "saves", "n1", time.Minute); err == nil {
			t.Fatal("unsigned accepted")
		}
	})
	t.Run("hs256 with pubkey", func(t *testing.T) {
		ek, ok := is.priv.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("not ecdsa")
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&ek.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: pubDER},
			(&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jwt.Signed(sig).Claims(base()).Claims(map[string]any{"nonce": "n1"}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.VerifyIDToken(ctx, raw, "saves", "n1", time.Minute); err == nil {
			t.Fatal("hs256 accepted")
		}
	})
	t.Run("unknown key", func(t *testing.T) {
		other := newIssuer(t, jose.ES256)
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other.priv},
			(&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jwt.Signed(sig).Claims(base()).Claims(map[string]any{"nonce": "n1"}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.VerifyIDToken(ctx, raw, "saves", "n1", time.Minute); err == nil {
			t.Fatal("foreign key accepted")
		}
	})
}

// TestOIDCProviderConcurrent hammers Discover and VerifyIDToken for the
// race detector.
func TestOIDCProviderConcurrent(t *testing.T) {
	is := newIssuer(t, jose.ES256)
	p := provFor(t, is)
	ctx := context.Background()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: is.priv},
		(&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(goodClaims(is, time.Now)).
		Claims(map[string]any{"nonce": "n1"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if _, err := p.Discover(ctx); err != nil {
					t.Error(err)
				}
				if _, _, err := p.VerifyIDToken(ctx, raw, "saves", "n1", time.Minute); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}
