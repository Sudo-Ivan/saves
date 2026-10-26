package metatest

import (
	"context"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
)

// TokensAudit exercises UpdateToken, events, usage, stats and purge.
func TokensAudit(t *testing.T, f Factory) {
	t.Helper()
	st := f(t, testclock.New(time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)))
	ctx := context.Background()
	u := mkUser(t, st, "tauditsub")
	now := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
	tok := meta.Token{ID: "t1", UserID: u.ID, Name: "n", Scopes: []string{"read"},
		CreatedAt: now}
	if err := st.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	// UpdateToken
	name := "renamed"
	if err := st.UpdateToken(ctx, "t1", meta.TokenPatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetToken(ctx, "t1")
	if got.Name != "renamed" {
		t.Fatalf("name=%q", got.Name)
	}
	exp := now.Add(24 * time.Hour)
	if err := st.UpdateToken(ctx, "t1", meta.TokenPatch{ExpiresAt: expPP(&exp)}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetToken(ctx, "t1")
	if got.ExpiresAt == nil {
		t.Fatal("expires not set")
	}
	var noExp *time.Time
	if err := st.UpdateToken(ctx, "t1", meta.TokenPatch{ExpiresAt: &noExp}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetToken(ctx, "t1")
	if got.ExpiresAt != nil {
		t.Fatal("expires not cleared")
	}
	cs := []string{"10.0.0.0/8"}
	if err := st.UpdateToken(ctx, "t1", meta.TokenPatch{CIDRs: &cs}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetToken(ctx, "t1")
	if len(got.AllowedCIDRs) != 1 {
		t.Fatal("cidrs not set")
	}
	empty := []string{}
	if err := st.UpdateToken(ctx, "t1", meta.TokenPatch{CIDRs: &empty}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetToken(ctx, "t1")
	if len(got.AllowedCIDRs) != 0 {
		t.Fatal("cidrs not cleared")
	}
	if err := st.UpdateToken(ctx, "nope", meta.TokenPatch{Name: &name}); err != meta.ErrNotFound {
		t.Fatalf("want ErrNotFound got %v", err)
	}
	if err := st.UpdateToken(ctx, "t1", meta.TokenPatch{}); err != nil {
		t.Fatal(err)
	}

	// Events: 120 rows sharing timestamps, paginate by 50.
	for i := 0; i < 120; i++ {
		at := now.Add(time.Duration(i%3) * time.Second) // ties
		id, _ := meta.NewID(now)
		kind := "created"
		if i%2 == 1 {
			kind = "renamed"
		}
		if err := st.InsertTokenEvent(ctx, meta.TokenEvent{
			ID: id, TokenID: "t1", UserID: u.ID, At: at, Kind: kind}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	count := 0
	for {
		ev, next, err := st.ListTokenEvents(ctx, "t1", "", cursor, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ev {
			if seen[e.ID] {
				t.Fatalf("duplicate %s", e.ID)
			}
			seen[e.ID] = true
			count++
		}
		if next == "" {
			break
		}
		cursor = next
		if count > 200 {
			t.Fatal("runaway pagination")
		}
	}
	if count != 120 {
		t.Fatalf("saw %d want 120", count)
	}
	// kind filter
	created, _, _ := st.ListTokenEvents(ctx, "t1", "created", "", 200)
	if len(created) != 60 {
		t.Fatalf("created=%d", len(created))
	}
	if _, _, err := st.ListTokenEvents(ctx, "t1", "", "!!", 50); err == nil {
		t.Fatal("malformed cursor should error")
	}
	// newest first
	page, _, _ := st.ListTokenEvents(ctx, "t1", "", "", 10)
	for i := 1; i < len(page); i++ {
		if page[i].At.After(page[i-1].At) {
			t.Fatal("not newest first")
		}
	}
}

func expPP(t *time.Time) **time.Time { return &t }

// TokensUsage covers upsert aggregation, stats and purge.
func TokensUsage(t *testing.T, f Factory) {
	st := f(t, testclock.New(time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)))
	ctx := context.Background()
	u := mkUser(t, st, "tusage")
	now := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
	tok := meta.Token{ID: "tu", UserID: u.ID, Name: "n", Scopes: []string{"read"}, CreatedAt: now}
	if err := st.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	h := now.UTC().Truncate(time.Hour)
	pairs, err := st.UpsertTokenUsage(ctx, []meta.UsageRow{
		{TokenID: "tu", IP: "1.1.1.1", Bucket: h, Requests: 3, LastSeen: now, UserAgent: "a"},
		{TokenID: "tu", IP: "2.2.2.2", Bucket: h, Requests: 1, LastSeen: now, UserAgent: "b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 2 {
		t.Fatalf("pairs=%v", pairs)
	}
	firsts := 0
	for _, p := range pairs {
		if p.First {
			firsts++
		}
	}
	if firsts == 0 {
		t.Fatal("no First reported for a fresh token")
	}
	// repeat: no new pairs, requests add up
	pairs, err = st.UpsertTokenUsage(ctx, []meta.UsageRow{
		{TokenID: "tu", IP: "1.1.1.1", Bucket: h, Requests: 2, LastSeen: now.Add(time.Minute), UserAgent: "a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("repeat upsert pairs=%v", pairs)
	}
	st2, _ := st.TokenStats(ctx, "tu")
	if st2.Total != 6 {
		t.Fatalf("total=%d want 6", st2.Total)
	}
	if len(st2.Daily) != 30 {
		t.Fatalf("daily len=%d", len(st2.Daily))
	}
	if st2.UniqueIPs30d != 2 {
		t.Fatalf("unique=%d", st2.UniqueIPs30d)
	}
	if len(st2.TopIPs) == 0 || st2.TopIPs[0].IP != "1.1.1.1" {
		t.Fatalf("top=%v", st2.TopIPs)
	}
	if st2.LastUse == nil || st2.LastUse.Before(now) {
		t.Fatal("last use")
	}
	// unknown token stats is zero without error
	z, err := st.TokenStats(ctx, "nope")
	if err != nil || z.Total != 0 {
		t.Fatalf("unknown stats: %v %v", z.Total, err)
	}
	// denied counts only denied_* kinds
	id, _ := meta.NewID(now)
	_ = st.InsertTokenEvent(ctx, meta.TokenEvent{ID: id, TokenID: "tu", UserID: u.ID, At: now, Kind: "denied_ip", IP: "9.9.9.9"})
	id2, _ := meta.NewID(now)
	_ = st.InsertTokenEvent(ctx, meta.TokenEvent{ID: id2, TokenID: "tu", UserID: u.ID, At: now, Kind: "created"})
	st3, _ := st.TokenStats(ctx, "tu")
	if st3.Denied["denied_ip"] != 1 || st3.Denied["created"] != 0 {
		t.Fatalf("denied=%v", st3.Denied)
	}
	// purge removes old, keeps new
	old := now.Add(-100 * 24 * time.Hour)
	oid, _ := meta.NewID(now)
	_ = st.InsertTokenEvent(ctx, meta.TokenEvent{ID: oid, TokenID: "tu", UserID: u.ID, At: old, Kind: "denied_ip"})
	_, _ = st.UpsertTokenUsage(ctx, []meta.UsageRow{{TokenID: "tu", IP: "3.3.3.3", Bucket: old, Requests: 1, LastSeen: old}})
	if err := st.PurgeTokenAudit(ctx, now.Add(-90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ev, _, _ := st.ListTokenEvents(ctx, "tu", "", "", 200)
	for _, e := range ev {
		if e.ID == oid {
			t.Fatal("old event not purged")
		}
	}
	st4, _ := st.TokenStats(ctx, "tu")
	found := false
	for _, ip := range st4.TopIPs {
		if ip.IP == "3.3.3.3" {
			found = true
		}
	}
	if found {
		t.Fatal("old usage not purged")
	}
}
