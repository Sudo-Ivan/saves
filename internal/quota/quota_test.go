// SPDX-License-Identifier: 0BSD

package quota

import (
	"testing"

	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
)

func TestForTierLimits(t *testing.T) {
	cfg := config.Defaults()
	cfg.Quota.DefaultTier = "free"
	cfg.Quota.AllowUnknownApps = ".*"
	cfg.Quota.Tiers["free"] = config.Tier{
		QuotaBytes: 1024, MaxSlots: 4, MaxSnapshotsPerSlot: 3,
		MaxFiles: 2, MaxFileBytes: 1 << 20, MaxSnapshotBytes: 4 << 20,
		Retention: config.RetentionPolicy{KeepLast: 10},
		Rate:      config.RateLimit{RequestsPerSec: 5, Burst: 5},
	}
	r := New(&cfg)
	e, err := r.For(meta.User{ID: "u"}, "app", false)
	if err != nil {
		t.Fatal(err)
	}
	if e.APILimits.MaxFiles != 2 || e.APILimits.MaxFileBytes != 1<<20 ||
		e.APILimits.MaxSnapshotBytes != 4<<20 {
		t.Fatalf("tier limits not applied: %+v", e.APILimits)
	}
	if e.KeepLast != 3 {
		t.Fatalf("KeepLast=%d want min(10,3)=3", e.KeepLast)
	}
}

func TestForZeroInherits(t *testing.T) {
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	r := New(&cfg)
	e, err := r.For(meta.User{ID: "u"}, "app", false)
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.Limits.APILimits()
	if e.APILimits.MaxFiles != g.MaxFiles {
		t.Fatal("zero tier did not inherit global")
	}
}

func TestForAppOverride(t *testing.T) {
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	cfg.Quota.Apps = map[string]config.AppPolicy{
		"x": {MaxFileBytes: 100},
	}
	r := New(&cfg)
	e, err := r.For(meta.User{ID: "u"}, "x", false)
	if err != nil {
		t.Fatal(err)
	}
	if e.APILimits.MaxFileBytes != 100 {
		t.Fatalf("app override not applied: %d", e.APILimits.MaxFileBytes)
	}
}
