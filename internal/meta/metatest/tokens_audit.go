package metatest

import (
	"context"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/Sudo-Ivan/saves/pkg/api"
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

// AppViz covers AppBytes, SnapshotActivity and bandwidth accounting.
func AppViz(t *testing.T, f Factory) {
	st := f(t, testclock.New(time.Date(2027, 3, 10, 12, 0, 0, 0, time.UTC)))
	ctx := context.Background()
	u := mkUser(t, st, "viz")
	q := int64(1 << 30)

	// app1: slot1 with head=200, slot2 with head replaced (only head counts)
	r1 := mkSnapshot(t, st, u.ID, "app1", "s1", []api.ChunkRef{chunkRef("v1", 200)}, q)
	storeAll(t, st, u.ID, r1.Snapshot.ID, []api.ChunkRef{chunkRef("v1", 200)})
	if _, err := st.CommitSnapshot(ctx, u.ID, r1.Snapshot.ID, meta.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	r2 := mkSnapshot(t, st, u.ID, "app1", "s2", []api.ChunkRef{chunkRef("v2", 100)}, q)
	storeAll(t, st, u.ID, r2.Snapshot.ID, []api.ChunkRef{chunkRef("v2", 100)})
	if _, err := st.CommitSnapshot(ctx, u.ID, r2.Snapshot.ID, meta.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	r3 := mkSnapshot(t, st, u.ID, "app1", "s2", []api.ChunkRef{chunkRef("v3", 500)}, q)
	storeAll(t, st, u.ID, r3.Snapshot.ID, []api.ChunkRef{chunkRef("v3", 500)})
	if _, err := st.CommitSnapshot(ctx, u.ID, r3.Snapshot.ID, meta.CommitOptions{ExpectedHead: r2.Snapshot.ID}); err != nil {
		t.Fatal(err)
	}
	// app2: pending only, counts 0
	r4 := mkSnapshot(t, st, u.ID, "app2", "s1", []api.ChunkRef{chunkRef("v4", 50)}, q)
	_ = r4
	// app3 with head
	r5 := mkSnapshot(t, st, u.ID, "app3", "s1", []api.ChunkRef{chunkRef("v5", 10)}, q)
	storeAll(t, st, u.ID, r5.Snapshot.ID, []api.ChunkRef{chunkRef("v5", 10)})
	if _, err := st.CommitSnapshot(ctx, u.ID, r5.Snapshot.ID, meta.CommitOptions{}); err != nil {
		t.Fatal(err)
	}

	apps, err := st.AppBytes(ctx, u.ID)
	if err != nil || len(apps) != 3 {
		t.Fatalf("apps=%v err=%v", apps, err)
	}
	// ordered by bytes desc: app1 (200+500=700), app3 (10), app2 (0)
	if apps[0].App != "app1" || apps[0].Bytes != 700 || apps[0].Slots != 2 {
		t.Fatalf("app1=%v", apps[0])
	}
	if apps[1].App != "app3" || apps[1].Bytes != 10 {
		t.Fatalf("app3=%v", apps[1])
	}
	if apps[2].App != "app2" || apps[2].Bytes != 0 {
		t.Fatalf("app2=%v", apps[2])
	}

	// SnapshotActivity: 4 committed on "today" in the test clock
	days, err := st.SnapshotActivity(ctx, u.ID, 30)
	if err != nil || len(days) != 30 {
		t.Fatalf("days=%d err=%v", len(days), err)
	}
	last := days[29]
	if last.Snapshots != 4 || last.Bytes != 810 {
		t.Fatalf("today=%v", last)
	}
	for _, d := range days[:29] {
		if d.Snapshots != 0 || d.Bytes != 0 {
			t.Fatalf("zero fill: %+v", d)
		}
	}
	big, err := st.SnapshotActivity(ctx, u.ID, 200)
	if err != nil || len(big) != 90 {
		t.Fatalf("cap=%d", len(big))
	}

	// Bandwidth additive across calls and users
	d0 := meta.BandwidthDay(time.Date(2027, 3, 10, 0, 0, 0, 0, time.UTC))
	if err := st.AddBandwidth(ctx, []meta.BandwidthRow{{UserID: u.ID, Day: d0, Up: 10, Down: 20}}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddBandwidth(ctx, []meta.BandwidthRow{
		{UserID: u.ID, Day: d0, Up: 5, Down: 7},
		{UserID: "other", Day: d0, Up: 1, Down: 1},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.BandwidthUsage(ctx, u.ID, d0, d0)
	if err != nil || len(rows) != 1 || rows[0].Up != 15 || rows[0].Down != 27 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	// range ordering
	d1 := meta.BandwidthDay(time.Date(2027, 3, 11, 0, 0, 0, 0, time.UTC))
	_ = st.AddBandwidth(ctx, []meta.BandwidthRow{{UserID: u.ID, Day: d1, Up: 1, Down: 1}})
	rows, _ = st.BandwidthUsage(ctx, u.ID, d0, d1)
	if len(rows) != 2 || rows[0].Day != d0 {
		t.Fatalf("range=%v", rows)
	}
	if err := st.PurgeBandwidth(ctx, d1); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.BandwidthUsage(ctx, u.ID, d0, d1)
	if len(rows) != 1 || rows[0].Day != d1 {
		t.Fatalf("after purge=%v", rows)
	}
	// first_use of BandwidthDay sanity
	if meta.BandwidthDay(time.Date(2027, 1, 9, 0, 0, 0, 0, time.UTC)) != 20270109 {
		t.Fatal("BandwidthDay")
	}
}

// AdminStore covers settings, invites, status, blocks, audit and stats.
func AdminStore(t *testing.T, f Factory) {
	st := f(t, testclock.New(time.Date(2027, 6, 1, 12, 0, 0, 0, time.UTC)))
	ctx := context.Background()
	u := mkUser(t, st, "adm")
	now := time.Date(2027, 6, 1, 12, 0, 0, 0, time.UTC)

	// settings
	if err := st.PutSetting(ctx, "k1", `"v"`, "actor"); err != nil {
		t.Fatal(err)
	}
	g, _ := st.GetSettings(ctx)
	if g["k1"].Value != `"v"` || g["k1"].UpdatedBy != "actor" {
		t.Fatalf("settings=%v", g)
	}
	_ = st.DeleteSetting(ctx, "k1")
	g, _ = st.GetSettings(ctx)
	if len(g) != 0 {
		t.Fatal("delete")
	}

	// invite: create, consume once with max_uses=1, second fails
	var hash [32]byte
	copy(hash[:], "invitehash000000000000000000000")
	if err := st.CreateInvite(ctx, meta.Invite{ID: "iv1", CodeHash: hash, Label: "l", MaxUses: 1, CreatedAt: &now}); err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumeInvite(ctx, hash, u.ID, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumeInvite(ctx, hash, u.ID, "1.2.3.4"); err != meta.ErrInviteInvalid {
		t.Fatalf("second use: %v", err)
	}
	inv, _ := st.ListInvites(ctx)
	if len(inv) != 1 || inv[0].Status != "exhausted" {
		t.Fatalf("invites=%v", inv)
	}

	// user status: ban then expire
	if err := st.SetUserStatus(ctx, meta.UserStatus{UserID: u.ID, State: "banned", Reason: "r", At: now, By: "adm"}); err != nil {
		t.Fatal(err)
	}
	ug, _ := st.GetUser(ctx, u.ID)
	if !ug.Disabled {
		t.Fatal("ban should disable")
	}
	until := now.Add(time.Hour)
	_ = st.SetUserStatus(ctx, meta.UserStatus{UserID: u.ID, State: "banned", At: now, Until: &until})
	ids, err := st.ExpireBans(ctx, now.Add(2*time.Hour))
	if err != nil || len(ids) != 1 {
		t.Fatalf("expire=%v %v", ids, err)
	}
	ug, _ = st.GetUser(ctx, u.ID)
	if ug.Disabled {
		t.Fatal("unban failed")
	}

	// ip blocks
	_ = st.AddIPBlock(ctx, meta.IPBlock{ID: "b1", CIDR: "10.0.0.0/8", CreatedAt: now})
	blocks, _ := st.ListIPBlocks(ctx)
	if len(blocks) != 1 {
		t.Fatal("blocks")
	}
	_ = st.DeleteIPBlock(ctx, "b1")

	// audit: insert 5, list with cursor and filter
	for i := 0; i < 5; i++ {
		id, err := meta.NewID(now.Add(time.Duration(i)))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.InsertAudit(ctx, []meta.AuditEvent{{ID: id, At: now.Add(time.Duration(i) * time.Second), Action: "ban", ActorID: "a", TargetID: u.ID, Detail: `{"r":1}`}}); err != nil {
			t.Fatal(err)
		}
	}
	ev, cur, err := st.ListAudit(ctx, meta.AuditFilter{}, "", 2)
	if err != nil || len(ev) != 2 || cur == "" {
		t.Fatalf("audit page: %v %v", len(ev), err)
	}
	ev2, _, _ := st.ListAudit(ctx, meta.AuditFilter{}, cur, 10)
	if len(ev2) != 3 {
		t.Fatalf("rest: %d", len(ev2))
	}
	bans, _, _ := st.ListAudit(ctx, meta.AuditFilter{Action: "ban"}, "", 10)
	if len(bans) != 5 {
		t.Fatalf("filter: %d", len(bans))
	}

	// stats additive + zero fill + gauges
	d := meta.BandwidthDay(now)
	_ = st.AddStats(ctx, []meta.StatsDelta{{Day: d, Signups: 2, BytesIn: 10}})
	_ = st.AddStats(ctx, []meta.StatsDelta{{Day: d, Signups: 1, BytesIn: 5}})
	_ = st.SetStatsGauges(ctx, d, 100, 3, 2)
	series, _ := st.StatsSeries(ctx, d-1, d)
	if len(series) != 2 || series[1].Signups != 3 || series[1].Storage != 100 {
		t.Fatalf("series=%v", series)
	}
	_ = st.TouchActivity(ctx, []meta.UserDay{{UserID: u.ID, Day: d}})
	_ = st.TouchActivity(ctx, []meta.UserDay{{UserID: u.ID, Day: d}})

	// admin totals + list
	tot, err := st.AdminTotals(ctx)
	if err != nil || tot.Users < 1 {
		t.Fatalf("totals=%v %v", tot, err)
	}
	rows, n, err := st.ListUsersAdmin(ctx, meta.UserFilter{}, 0, 10)
	if err != nil || n < 1 || len(rows) < 1 {
		t.Fatalf("list=%v %v", n, err)
	}
	if rows[0].Username == "" && rows[0].User.Subject == "" {
		t.Fatal("row empty")
	}
}
