package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func TestParseTTL(t *testing.T) {
	for _, v := range []string{"720h", "30d", "90m", "365d"} {
		if _, err := ParseTTL(v); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"59s", "0", "-1h", "junk", "3661d"} {
		if _, err := ParseTTL(v); err == nil {
			t.Fatalf("%s should fail", v)
		}
	}
}

func TestResolveTokenExpiry(t *testing.T) {
	now := time.Now()
	maxTTL := 90 * 24 * time.Hour
	if v, err := ResolveTokenExpiry(now, 0, nil, true); v != nil || err != nil {
		t.Fatal(v, err)
	}
	v, err := ResolveTokenExpiry(now, maxTTL, nil, true)
	if err != nil || v == nil {
		t.Fatal("max_ttl should fill expiry")
	}
	if _, err := ResolveTokenExpiry(now, maxTTL, nil, false); err == nil {
		t.Fatal("edit without expiry under max_ttl should fail")
	}
	past := now.Add(-time.Hour)
	if _, err := ResolveTokenExpiry(now, 0, &past, true); err == nil {
		t.Fatal("past")
	}
	nw := now
	if _, err := ResolveTokenExpiry(now, 0, &nw, true); err == nil {
		t.Fatal("exactly now")
	}
	far := now.Add(MaxTokenLifetime + time.Hour)
	if _, err := ResolveTokenExpiry(now, 0, &far, true); err == nil {
		t.Fatal("over 10 years")
	}
	over := now.Add(maxTTL + time.Hour)
	if _, err := ResolveTokenExpiry(now, maxTTL, &over, true); err == nil {
		t.Fatal("over max_ttl")
	}
	ok := now.Add(time.Hour)
	if v, err := ResolveTokenExpiry(now, maxTTL, &ok, true); err != nil || !v.Equal(ok) {
		t.Fatal(v, err)
	}
}

func TestNormalizeCIDRs(t *testing.T) {
	got, err := NormalizeCIDRs([]string{"10.0.0.1", "10.0.0.0/8"})
	if err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	if got[0] != "10.0.0.1/32" {
		t.Fatalf("got=%v", got)
	}
	if _, err := NormalizeCIDRs([]string{"0.0.0.0/0"}); err == nil {
		t.Fatal("should reject /0")
	}
}

func mkP(id string, s auth.Scope, apps []string) auth.Principal {
	return auth.Principal{User: meta.User{ID: id}, Scopes: s, Apps: apps}
}

func TestCreateTokenEscalation(t *testing.T) {
	s, m, _, _ := setup(t)
	ctx := context.Background()
	owner := mkP("o1", auth.ScopeRead, nil)
	owner.User.ID = principal(t, m, "owner", auth.ScopeRead).User.ID

	// empty scopes rejected
	if _, err := s.CreateToken(ctx, owner, owner.User.ID, "x", nil, nil, nil, nil); err == nil {
		t.Fatal("empty scopes")
	}
	// read-only cannot mint write or admin
	for _, sc := range [][]string{{"write"}, {"admin"}, {"read", "write"}} {
		if _, err := s.CreateToken(ctx, owner, owner.User.ID, "x", sc, nil, nil, nil); err == nil {
			t.Fatalf("read-only minted %v", sc)
		}
	}
	// non-admin cannot mint admin
	wr := principal(t, m, "wr", auth.ScopeRead|auth.ScopeWrite)
	wr.Scopes = auth.ScopeRead | auth.ScopeWrite
	if _, err := s.CreateToken(ctx, wr, wr.User.ID, "x", []string{"admin"}, nil, nil, nil); err == nil {
		t.Fatal("non-admin minted admin")
	}
	// app allowlist: outside rejected, empty inherits
	ar := principal(t, m, "ar", auth.ScopeRead)
	ar.Apps = []string{"game"}
	if _, err := s.CreateToken(ctx, ar, ar.User.ID, "x", []string{"read"}, []string{"other"}, nil, nil); err == nil {
		t.Fatal("app outside allowlist")
	}
	f, err := s.CreateToken(ctx, ar, ar.User.ID, "x", []string{"read"}, nil, nil, nil)
	if err != nil || len(f.Token.Apps) != 1 || f.Token.Apps[0] != "game" {
		t.Fatal("should inherit caller allowlist")
	}
	// admin mints admin
	adm := principal(t, m, "adm", auth.ScopeAdmin)
	adm.Scopes = auth.ScopeAdmin
	if _, err := s.CreateToken(ctx, adm, adm.User.ID, "x", []string{"admin"}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	// name over 128
	long := strings.Repeat("x", 129)
	if _, err := s.CreateToken(ctx, adm, adm.User.ID, long, []string{"read"}, nil, nil, nil); err == nil {
		t.Fatal("long name")
	}
	// secret hash not returned in principal-facing Token
	adm.Scopes |= auth.ScopeRead
	f2, _ := s.CreateToken(ctx, adm, adm.User.ID, "x", []string{"read"}, nil, nil, nil)
	if f2.Token.SecretHash != [32]byte{} {
		t.Fatal("secret hash leaked")
	}
}

func TestUpdateTokenRules(t *testing.T) {
	s, m, _, _ := setup(t)
	s.TokenMaxTTL = 24 * time.Hour
	s.AuditEnabled = true
	var inv []string
	s.TokenInvalidator = func(id string) { inv = append(inv, id) }
	ctx := context.Background()
	adm := principal(t, m, "adm2", auth.ScopeAdmin|auth.ScopeRead)
	f, err := s.CreateToken(ctx, adm, adm.User.ID, "x", []string{"read"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stranger := principal(t, m, "stranger", auth.ScopeRead)
	nm := "new"
	// stranger forbidden
	if err := s.UpdateToken(ctx, stranger, f.Token.ID, meta.TokenPatch{Name: &nm}); err == nil {
		t.Fatal("stranger edited")
	}
	// owner edit works, invalidator fires
	if err := s.UpdateToken(ctx, adm, f.Token.ID, meta.TokenPatch{Name: &nm}); err != nil {
		t.Fatal(err)
	}
	if len(inv) != 1 {
		t.Fatal("invalidator not called")
	}
	// expiry beyond max_ttl rejected
	far := time.Now().Add(48 * time.Hour)
	if err := s.UpdateToken(ctx, adm, f.Token.ID, meta.TokenPatch{ExpiresAt: tt(&far)}); err == nil {
		t.Fatal("extension beyond max_ttl")
	}
	// removing expiry rejected when max_ttl set
	var nullExp *time.Time
	if err := s.UpdateToken(ctx, adm, f.Token.ID, meta.TokenPatch{ExpiresAt: &nullExp}); err == nil {
		t.Fatal("expiry removal under max_ttl")
	}
	// past rejected
	past := time.Now().Add(-time.Hour)
	if err := s.UpdateToken(ctx, adm, f.Token.ID, meta.TokenPatch{ExpiresAt: tt(&past)}); err == nil {
		t.Fatal("past expiry")
	}
	// cidrs normalized
	cs := []string{"10.0.0.1"}
	if err := s.UpdateToken(ctx, adm, f.Token.ID, meta.TokenPatch{CIDRs: &cs}); err != nil {
		t.Fatal(err)
	}
	g, _ := s.Meta.GetToken(ctx, f.Token.ID)
	if len(g.AllowedCIDRs) != 1 || g.AllowedCIDRs[0] != "10.0.0.1/32" {
		t.Fatalf("cidrs=%v", g.AllowedCIDRs)
	}
	// audit event written for the cidr change
	ev, _, _ := s.Meta.ListTokenEvents(ctx, f.Token.ID, "cidr_changed", "", 10)
	if len(ev) == 0 || ev[0].ActorID != adm.User.ID {
		t.Fatalf("events=%v", ev)
	}
	// revoke then edit conflicts
	if err := s.RevokeToken(ctx, adm, f.Token.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateToken(ctx, adm, f.Token.ID, meta.TokenPatch{Name: &nm}); err == nil {
		t.Fatal("edit revoked token")
	}
}

func TestTokenStatsAuthz(t *testing.T) {
	s, m, _, _ := setup(t)
	ctx := context.Background()
	adm := principal(t, m, "adm3", auth.ScopeAdmin|auth.ScopeRead)
	f, _ := s.CreateToken(ctx, adm, adm.User.ID, "x", []string{"read"}, nil, nil, nil)
	stranger := principal(t, m, "stranger2", auth.ScopeRead)
	if _, err := s.TokenStats(ctx, stranger, f.Token.ID); err == nil {
		t.Fatal("stranger stats")
	}
	if _, _, err := s.TokenEvents(ctx, stranger, f.Token.ID, "", "", 10); err == nil {
		t.Fatal("stranger events")
	}
	if _, err := s.TokenStats(ctx, adm, f.Token.ID); err != nil {
		t.Fatal(err)
	}
	// ListTokens returns no secret hash
	ts, err := s.ListTokens(ctx, adm, adm.User.ID)
	if err != nil || len(ts) == 0 {
		t.Fatal(err)
	}
	for _, tk := range ts {
		if tk.SecretHash != [32]byte{} {
			t.Fatal("list leaks secret hash")
		}
	}
	var _ = api.Problem{}
}

func tt(t *time.Time) **time.Time { return &t }
