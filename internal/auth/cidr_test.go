package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

func TestValidateCIDRs(t *testing.T) {
	cases := []struct {
		in  string
		out int
		bad bool
	}{
		{"10.0.0.5", 1, false},
		{"10.0.0.7/8", 1, false},
		{"fd00::1", 1, false},
		{"::ffff:10.0.0.1", 1, false},
		{"10.0.0.0/8, 192.168.0.0/16", 2, false},
		{"10.0.0.0/8\n192.168.0.0/16", 2, false},
		{"10.0.0.1,10.0.0.1", 1, false},
		{"0.0.0.0/0", 0, true},
		{"::/0", 0, true},
		{"garbage", 0, true},
		{"10.0.0." + strings.Repeat("1", 60), 0, true},
	}
	for _, c := range cases {
		got, err := ValidateCIDRs(c.in)
		if c.bad != (err != nil) {
			t.Fatalf("%q err=%v", c.in, err)
		}
		if err == nil && len(got) != c.out {
			t.Fatalf("%q n=%d", c.in, len(got))
		}
	}
	var big strings.Builder
	for i := 0; i < 17; i++ {
		big.WriteString(fmt.Sprintf("10.0.0.%d/32\n", i+1))
	}
	if _, err := ValidateCIDRs(big.String()); err == nil {
		t.Fatal("17 distinct entries should fail")
	}
	var ok strings.Builder
	for i := 0; i < 16; i++ {
		ok.WriteString(fmt.Sprintf("10.0.0.%d/32\n", i+1))
	}
	if got, err := ValidateCIDRs(ok.String()); err != nil || len(got) != 16 {
		t.Fatal(err, len(got))
	}
}

func TestParseCIDRs(t *testing.T) {
	got, err := ParseCIDRs([]string{"10.0.0.1", "fd00::/8", "::ffff:10.0.0.0/104"})
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	if got[0].String() != "10.0.0.1/32" {
		t.Fatalf("got[0]=%s", got[0])
	}
	if got[2].String() != "10.0.0.0/8" {
		t.Fatalf("mapped prefix=%s", got[2])
	}
	if _, err := ParseCIDRs([]string{"::ffff:10.0.0.0/95"}); err == nil {
		t.Fatal("bits<96 mapped should fail")
	}
}

func FuzzValidateCIDRs(f *testing.F) {
	f.Add("10.0.0.1\n192.168.0.0/16")
	f.Add("::/0")
	f.Fuzz(func(t *testing.T, in string) {
		out, err := ValidateCIDRs(in)
		if err != nil {
			return
		}
		again, err := ValidateCIDRs(strings.Join(out, "\n"))
		if err != nil || len(again) != len(out) {
			t.Fatalf("re-validate %q: %v %v", out, again, err)
		}
	})
}

func cidrReq(ip, auth string) *http.Request {
	r, _ := http.NewRequest("GET", "/v1/x", nil)
	r.RemoteAddr = ip + ":1234"
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	return r
}

func mkCIDRTok(t *testing.T, s meta.Store, cidr string) string {
	u, _, _ := s.UpsertUser(context.Background(), "cidr", "free")
	id, _, full, hash, _ := GenerateToken()
	s.CreateToken(context.Background(), meta.Token{ID: id, UserID: u.ID,
		SecretHash: hash, Scopes: []string{"read"}, CreatedAt: time.Now(),
		AllowedCIDRs: []string{cidr}})
	return full
}

func TestTokenAuthCIDR(t *testing.T) {
	s, c := store(t)
	a := &TokenAuthenticator{Meta: s, Clock: c.NowFunc()}
	ctx := context.Background()
	full := mkCIDRTok(t, s, "10.0.0.0/8")
	// inside allowlist
	if _, err := a.Authenticate(ctx, cidrReq("10.1.2.3", full)); err != nil {
		t.Fatal(err)
	}
	// outside
	if _, err := a.Authenticate(ctx, cidrReq("203.0.113.9", full)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("want ErrUnauthorized")
	}
	// cached path enforces too: first from allowed then denied within TTL
	a2 := &TokenAuthenticator{Meta: s, Clock: c.NowFunc(), CacheTTL: time.Minute}
	if _, err := a2.Authenticate(ctx, cidrReq("10.9.9.9", full)); err != nil {
		t.Fatal(err)
	}
	if _, err := a2.Authenticate(ctx, cidrReq("203.0.113.9", full)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("cached path must enforce CIDR")
	}
	// IPv6
	full6 := mkCIDRTok(t, s, "fd00::/8")
	if _, err := a.Authenticate(ctx, cidrReq("fd00::9", full6)); err != nil {
		t.Fatal(err)
	}
}

func TestTokenAuthCIDRProxy(t *testing.T) {
	s, c := store(t)
	trust, _ := netip.ParsePrefix("10.0.0.0/8")
	a := &TokenAuthenticator{Meta: s, Clock: c.NowFunc(),
		TrustedProxies: []netip.Prefix{trust}, RealIPHeader: "X-Real-IP"}
	ctx := context.Background()
	full := mkCIDRTok(t, s, "203.0.113.0/24")
	// trusted proxy forwards an allowed client IP via XFF
	r := cidrReq("10.0.0.1", full)
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if _, err := a.Authenticate(ctx, r); err != nil {
		t.Fatal(err)
	}
	// untrusted peer spoofing an allowed XFF stays denied
	r2 := cidrReq("192.0.2.9", full)
	r2.Header.Set("X-Forwarded-For", "203.0.113.7")
	if _, err := a.Authenticate(ctx, r2); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("spoofed XFF should not satisfy allowlist")
	}
	// real IP header from trusted peer
	r3 := cidrReq("10.0.0.1", full)
	r3.Header.Set("X-Real-IP", "203.0.113.7")
	if _, err := a.Authenticate(ctx, r3); err != nil {
		t.Fatal(err)
	}
	// real IP header ignored from untrusted peer
	r4 := cidrReq("192.0.2.9", full)
	r4.Header.Set("X-Real-IP", "203.0.113.7")
	if _, err := a.Authenticate(ctx, r4); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("real-ip from untrusted peer ignored")
	}
}

func TestTokenAuthDeniedEvents(t *testing.T) {
	s, c := store(t)
	var events []meta.TokenEvent
	a := &TokenAuthenticator{Meta: s, Clock: c.NowFunc(),
		RecordEvent: func(e meta.TokenEvent) { events = append(events, e) },
	}
	ctx := context.Background()
	u, _, _ := s.UpsertUser(context.Background(), "de", "free")
	id, _, full, hash, _ := GenerateToken()
	s.CreateToken(context.Background(), meta.Token{ID: id, UserID: u.ID,
		SecretHash: hash, Scopes: []string{"read"}, CreatedAt: time.Now(),
		AllowedCIDRs: []string{"10.0.0.0/8"}})
	// wrong secret records nothing
	if _, err := a.Authenticate(ctx, cidrReq("203.0.113.9", "sv1_"+id+"_AAAA")); !errors.Is(err, ErrUnauthorized) {
		t.Fatal()
	}
	if len(events) != 0 {
		t.Fatal("event recorded for bad secret")
	}
	// right secret, wrong ip: one denied_ip
	_, _ = a.Authenticate(ctx, cidrReq("203.0.113.9", full))
	if len(events) != 1 || events[0].Kind != "denied_ip" {
		t.Fatalf("events=%v", events)
	}
	// same token+ip within a minute: still one
	_, _ = a.Authenticate(ctx, cidrReq("203.0.113.9", full))
	if len(events) != 1 {
		t.Fatal("denied rate limit failed")
	}
	c.Add(2 * time.Minute)
	_, _ = a.Authenticate(ctx, cidrReq("203.0.113.9", full))
	if len(events) != 2 {
		t.Fatal("denied after a minute should record")
	}
	// expired records denied_expired
	past := time.Now().Add(-time.Hour)
	id2, _, full2, hash2, _ := GenerateToken()
	s.CreateToken(context.Background(), meta.Token{ID: id2, UserID: u.ID,
		SecretHash: hash2, Scopes: []string{"read"}, CreatedAt: time.Now(), ExpiresAt: &past})
	_, _ = a.Authenticate(ctx, cidrReq("203.0.113.9", full2))
	found := false
	for _, e := range events {
		if e.Kind == "denied_expired" {
			found = true
		}
	}
	if !found {
		t.Fatal("no denied_expired")
	}
}
