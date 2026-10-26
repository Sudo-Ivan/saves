// SPDX-License-Identifier: 0BSD

package settings

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
)

type sink struct{ ev []meta.AuditEvent }

func (s *sink) Record(ctx context.Context, e meta.AuditEvent) { s.ev = append(s.ev, e) }

func store(t *testing.T) meta.Store {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "m.db"), meta.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mgr(t *testing.T) (*Manager, meta.Store) {
	st := store(t)
	cfg := config.Defaults()
	m := New(st, &cfg, nil)
	if err := m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m, st
}

func jm(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestValidate(t *testing.T) {
	m, _ := mgr(t)
	ctx := context.Background()
	bad := []map[string]json.RawMessage{
		{"registration.mode": jm("bogus")},
		{"registration.unknown": jm(1)},
		{"site.announcement_level": jm("error")},
		{"site.terms_url": jm("javascript:alert(1)")},
		{"site.terms_url": jm("http://x")}, // only https, mailto or relative
		{"registration.max_per_ip_per_day": jm(-1)},
		{"token.max_ttl": jm("not-a-duration")},
		{"nope.key": jm(1)},
	}
	for i, p := range bad {
		if _, err := m.Update(ctx, "a", p); err == nil {
			t.Fatalf("case %d should fail", i)
		}
	}
	ok := []map[string]json.RawMessage{
		{"registration.mode": jm("invite")},
		{"site.terms_url": jm("https://example.com/t")},
		{"site.contact": jm("mailto:a@b.c")},
		{"site.contact": jm("/contact")},
		{"site.announcement_text": jm("hi")},
		{"token.max_per_user": jm(5)},
	}
	for _, p := range ok {
		if _, err := m.Update(ctx, "a", p); err != nil {
			t.Fatalf("%v: %v", p, err)
		}
	}
	// tier map missing default tier
	patch := map[string]json.RawMessage{
		"quota.default_tier": jm("pro"),
		"quota.tiers":        jm(map[string]any{"free": map[string]any{}}),
	}
	if _, err := m.Update(ctx, "a", patch); err == nil {
		t.Fatal("missing default tier should fail")
	}
}

func TestUpdateResetOverrides(t *testing.T) {
	m, st := mgr(t)
	ctx := context.Background()
	sk := &sink{}
	m.Sink = sk
	// update
	ch, err := m.Update(ctx, "admin", map[string]json.RawMessage{"site.name": jm("other")})
	if err != nil || len(ch) != 1 {
		t.Fatal(err)
	}
	if m.Effective().SiteName != "other" {
		t.Fatal("not effective")
	}
	if len(m.Overrides()) != 1 || m.Overrides()[0].UpdatedBy != "admin" {
		t.Fatal("override not recorded")
	}
	if len(sk.ev) != 1 || sk.ev[0].TargetID != "site.name" {
		t.Fatalf("audit=%v", sk.ev)
	}
	// equal to default clears override
	def := config.Defaults().Web.InstanceName
	if _, err := m.Update(ctx, "admin", map[string]json.RawMessage{"site.name": jm(def)}); err != nil {
		t.Fatal(err)
	}
	if len(m.Overrides()) != 0 {
		t.Fatal("equal-to-default should clear the override")
	}
	// reset
	if err := m.Reset(ctx, "admin", "site.name"); err != nil {
		t.Fatal(err)
	}
	if m.Effective().SiteName != def || len(m.Overrides()) != 0 {
		t.Fatal("reset failed")
	}
	rows, _ := st.GetSettings(ctx)
	if len(rows) != 0 {
		t.Fatal("persisted override remains")
	}
}

func TestSubscribeAndConverge(t *testing.T) {
	st := store(t)
	cfg := config.Defaults()
	m1 := New(st, &cfg, nil)
	_ = m1.Load(context.Background())
	var gotOld, gotNew Values
	m1.Subscribe(func(o, n Values) { gotOld, gotNew = o, n })
	if _, err := m1.Update(context.Background(), "a", map[string]json.RawMessage{"site.name": jm("v2")}); err != nil {
		t.Fatal(err)
	}
	if gotOld.SiteName == gotNew.SiteName || gotNew.SiteName != "v2" {
		t.Fatal("subscriber")
	}
	// second manager converges via Load
	m2 := New(st, &cfg, nil)
	_ = m2.Load(context.Background())
	if m2.Effective().SiteName != "v2" {
		t.Fatal("converge")
	}
	// SetFileConfig: defaults change, override wins
	cfg2 := config.Defaults()
	cfg2.Web.InstanceName = "filechanged"
	m1.SetFileConfig(&cfg2)
	if m1.Effective().SiteName != "v2" {
		t.Fatal("override should win over file default")
	}
	m2.SetFileConfig(&cfg2)
	if m2.Effective().SiteName != "v2" {
		t.Fatal("m2 should also see the persisted override")
	}
}
