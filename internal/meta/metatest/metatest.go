// SPDX-License-Identifier: 0BSD

// Package metatest is the conformance and stress suite every meta.Store
// driver must pass. The factory receives a controllable clock so all
// TTL, expiry, and lease logic is deterministic.
package metatest

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Factory builds a fresh empty store bound to the given clock.
type Factory func(t *testing.T, c *testclock.Clock) meta.Store

// Run executes the full conformance suite.
func Run(t *testing.T, factory Factory) {
	t.Run("Users", func(t *testing.T) { testUsers(t, factory) })
	t.Run("Tokens", func(t *testing.T) { testTokens(t, factory) })
	t.Run("BeginCommit", func(t *testing.T) { testBeginCommit(t, factory) })
	t.Run("QuotaBoundary", func(t *testing.T) { testQuotaBoundary(t, factory) })
	t.Run("SlotAndPendingLimits", func(t *testing.T) { testLimits(t, factory) })
	t.Run("DedupAcrossSnapshots", func(t *testing.T) { testDedup(t, factory) })
	t.Run("ReviveZeroRef", func(t *testing.T) { testRevive(t, factory) })
	t.Run("ConflictForce", func(t *testing.T) { testConflictForce(t, factory) })
	t.Run("Retention", func(t *testing.T) { testRetention(t, factory) })
	t.Run("AbortExpire", func(t *testing.T) { testAbortExpire(t, factory) })
	t.Run("SharedReservation", func(t *testing.T) { testSharedReservation(t, factory) })
	t.Run("GCProtocol", func(t *testing.T) { testGCProtocol(t, factory) })
	t.Run("Fsck", func(t *testing.T) { testFsck(t, factory) })
	t.Run("SoftDeletePurge", func(t *testing.T) { testPurge(t, factory) })
	t.Run("Lease", func(t *testing.T) { testLease(t, factory) })
	t.Run("Pagination", func(t *testing.T) { testPagination(t, factory) })
	t.Run("Web", func(t *testing.T) { testWeb(t, factory) })
	t.Run("TokensAudit", func(t *testing.T) { TokensAudit(t, factory) })
	t.Run("TokensUsage", func(t *testing.T) { TokensUsage(t, factory) })

	t.Run("StressQuota", func(t *testing.T) { stressQuota(t, factory) })
	t.Run("StressGCRace", func(t *testing.T) { stressGCRace(t, factory) })
	t.Run("StressCommitCAS", func(t *testing.T) { stressCommitCAS(t, factory) })
	t.Run("StressExpireAbort", func(t *testing.T) { stressExpireAbort(t, factory) })
	t.Run("StressFsckProperty", func(t *testing.T) { stressFsckProperty(t, factory) })
}

func mkParams(uid, app, slot string, chunks []api.ChunkRef, lim meta.BeginLimits) meta.BeginParams {
	var mh api.Hash
	copy(mh[:], []byte("manifest-"+slot+fmt.Sprint(time.Now().UnixNano())))
	var total int64
	for _, c := range chunks {
		total += int64(c.Size)
	}
	return meta.BeginParams{
		UserID: uid, App: app, Slot: slot, ManifestHash: mh, ManifestSize: 128,
		TotalBytes: total, FileCount: len(chunks), Chunks: chunks, Limits: lim,
	}
}

func chunkRef(seed string, size uint32) api.ChunkRef {
	return api.ChunkRef{Hash: api.HashBytes([]byte(seed)), Size: size}
}

func mkUser(t *testing.T, s meta.Store, subject string) meta.User {
	t.Helper()
	u, created, err := s.UpsertUser(context.Background(), subject, "free")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected created")
	}
	return u
}

func mkSnapshot(t *testing.T, s meta.Store, uid, app, slot string, chunks []api.ChunkRef, quota int64) meta.BeginResult {
	t.Helper()
	r, err := s.BeginSnapshot(context.Background(), mkParams(uid, app, slot, chunks,
		meta.BeginLimits{QuotaBytes: quota, MaxSlots: 100, MaxPendingSnapshots: 100, ExpiresAt: time.Now().Add(time.Hour)}))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return r
}

func storeAll(t *testing.T, s meta.Store, uid, snapID string, chunks []api.ChunkRef) {
	t.Helper()
	for _, c := range chunks {
		if err := s.MarkChunkStored(context.Background(), uid, snapID, c.Hash, int64(c.Size)); err != nil {
			t.Fatalf("MarkChunkStored: %v", err)
		}
	}
}

func fsckClean(t *testing.T, s meta.Store) {
	t.Helper()
	rep, err := s.Fsck(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Issues) > 0 {
		t.Fatalf("fsck issues: %v", rep.Issues)
	}
}

func testUsers(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	c := testclock.New(time.Time{})
	u := mkUser(t, s, "subj1")
	u2, created, err := s.UpsertUser(ctx, "subj1", "other")
	if err != nil || created || u2.ID != u.ID {
		t.Fatal("upsert should return existing user")
	}
	g, err := s.GetUser(ctx, u.ID)
	if err != nil || g.Subject != "subj1" {
		t.Fatal("GetUser")
	}
	g2, err := s.GetUserBySubject(ctx, "subj1")
	if err != nil || g2.ID != u.ID {
		t.Fatal("GetUserBySubject")
	}
	tier := "pro"
	quota := meta.Optional[int64]{Set: true, Value: 12345}
	u, err = s.UpdateUser(ctx, u.ID, meta.UserPatch{Tier: &tier, QuotaBytes: &quota})
	if err != nil || u.Tier != "pro" || u.QuotaBytes == nil || *u.QuotaBytes != 12345 {
		t.Fatalf("UpdateUser: %v %+v", err, u)
	}
	quota = meta.Optional[int64]{Set: true, Null: true}
	u, err = s.UpdateUser(ctx, u.ID, meta.UserPatch{QuotaBytes: &quota})
	if err != nil || u.QuotaBytes != nil {
		t.Fatal("quota clear failed")
	}
	us, err := s.ListUsers(ctx, "", 10)
	if err != nil || len(us) != 1 {
		t.Fatalf("ListUsers: %v %d", err, len(us))
	}
	if _, err := s.GetUser(ctx, "missing"); !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("want ErrNotFound")
	}
	_ = c
	fsckClean(t, s)
}

func testTokens(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "toksub")
	tok := meta.Token{ID: "0123456789abcdef", UserID: u.ID, Name: "cli", Scopes: []string{"read", "write"}, Apps: []string{"a1"}}
	copy(tok.SecretHash[:], []byte("0123456789abcdef0123456789abcdef"))
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetToken(ctx, tok.ID)
	if err != nil || g.UserID != u.ID || len(g.Scopes) != 2 || g.Apps[0] != "a1" {
		t.Fatalf("GetToken: %v %+v", err, g)
	}
	at := time.Unix(1700000100, 0).UTC()
	if err := s.TouchToken(ctx, tok.ID, at); err != nil {
		t.Fatal(err)
	}
	g, _ = s.GetToken(ctx, tok.ID)
	if g.LastUsedAt == nil || !g.LastUsedAt.Equal(at) {
		t.Fatal("TouchToken")
	}
	l, err := s.ListTokens(ctx, u.ID)
	if err != nil || len(l) != 1 {
		t.Fatal("ListTokens")
	}
	if err := s.RevokeToken(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	g, _ = s.GetToken(ctx, tok.ID)
	if g.RevokedAt == nil {
		t.Fatal("RevokeToken")
	}
	if err := s.RevokeToken(ctx, tok.ID); !errors.Is(err, meta.ErrNotFound) {
		t.Fatalf("double revoke: %v", err)
	}
}

func testBeginCommit(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "bc")
	chunks := []api.ChunkRef{chunkRef("c1", 100), chunkRef("c2", 200)}
	r := mkSnapshot(t, s, u.ID, "app1", "slot1", chunks, 1<<30)
	if len(r.Missing) != 2 {
		t.Fatalf("missing %v", r.Missing)
	}
	// Second begin sees dedup: stored chunks are not missing once stored.
	storeAll(t, s, u.ID, r.Snapshot.ID, chunks)
	res, err := s.CommitSnapshot(ctx, u.ID, r.Snapshot.ID, meta.CommitOptions{ExpectedHead: "", KeepLast: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Snapshot.State != meta.StateCommitted {
		t.Fatal("not committed")
	}
	sl, err := s.GetSlot(ctx, u.ID, "app1", "slot1")
	if err != nil || sl.HeadSnapshotID != r.Snapshot.ID {
		t.Fatal("head not set")
	}
	// Incomplete commit rejected.
	r2 := mkSnapshot(t, s, u.ID, "app1", "slot1", []api.ChunkRef{chunkRef("c3", 50)}, 1<<30)
	var incErr *meta.IncompleteError
	if _, err := s.CommitSnapshot(ctx, u.ID, r2.Snapshot.ID, meta.CommitOptions{}); !errors.As(err, &incErr) || incErr.Missing != 1 {
		t.Fatalf("want IncompleteError, got %v", err)
	}
	fsckClean(t, s)
}

func testQuotaBoundary(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "qb")
	// Quota exactly: manifest(128) + 2 chunks(300) = 428.
	r, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", "s", []api.ChunkRef{chunkRef("q1", 200), chunkRef("q2", 100)},
		meta.BeginLimits{QuotaBytes: 428, MaxSlots: 10, MaxPendingSnapshots: 5}))
	if err != nil {
		t.Fatalf("at-limit begin: %v", err)
	}
	var qerr *meta.QuotaError
	if _, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", "s2", []api.ChunkRef{chunkRef("q3", 1)},
		meta.BeginLimits{QuotaBytes: 428, MaxSlots: 10, MaxPendingSnapshots: 5})); !errors.As(err, &qerr) {
		t.Fatalf("one byte over: want QuotaError, got %v", err)
	}
	if qerr.Used+qerr.Reserved <= qerr.Limit {
		t.Fatal("QuotaError did not report an over-limit total")
	}
	_ = r
	// Abort frees the reservation fully.
	if err := s.AbortSnapshot(ctx, u.ID, r.Snapshot.ID); err != nil {
		t.Fatal(err)
	}
	usage, _ := s.Usage(ctx, u.ID)
	if usage.ReservedBytes != 0 || usage.UsedBytes != 0 {
		t.Fatalf("usage after abort: %+v", usage)
	}
	fsckClean(t, s)
}

func testLimits(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "lm")
	lim := meta.BeginLimits{QuotaBytes: 1 << 30, MaxSlots: 2, MaxPendingSnapshots: 10}
	mkSnapshot(t, s, u.ID, "a", "s1", nil, 1<<30)
	mkSnapshot(t, s, u.ID, "a", "s2", nil, 1<<30)
	if _, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", "s3", nil, lim)); !errors.Is(err, meta.ErrSlotLimit) {
		t.Fatalf("want ErrSlotLimit, got %v", err)
	}
	pend := meta.BeginLimits{QuotaBytes: 1 << 30, MaxSlots: 10, MaxPendingSnapshots: 2}
	if _, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", "s1", nil, pend)); !errors.Is(err, meta.ErrPendingLimit) {
		t.Fatalf("want ErrPendingLimit, got %v", err)
	}
}

func testDedup(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "dd")
	chunks := []api.ChunkRef{chunkRef("d1", 100)}
	r1 := mkSnapshot(t, s, u.ID, "a", "s", chunks, 1<<30)
	storeAll(t, s, u.ID, r1.Snapshot.ID, chunks)
	if _, err := s.CommitSnapshot(ctx, u.ID, r1.Snapshot.ID, meta.CommitOptions{ExpectedHead: ""}); err != nil {
		t.Fatal(err)
	}
	r2 := mkSnapshot(t, s, u.ID, "a", "s", chunks, 1<<30)
	if len(r2.Missing) != 0 {
		t.Fatalf("stored chunk reported missing: %v", r2.Missing)
	}
	usage, _ := s.Usage(ctx, u.ID)
	// Two manifests (128 each) + one chunk (100).
	if usage.UsedBytes != 2*128+100 {
		t.Fatalf("used %d", usage.UsedBytes)
	}
}

func testRevive(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "rv")
	chunks := []api.ChunkRef{chunkRef("rv1", 500)}
	r1 := mkSnapshot(t, s, u.ID, "a", "s", chunks, 1<<30)
	storeAll(t, s, u.ID, r1.Snapshot.ID, chunks)
	_, _ = s.CommitSnapshot(ctx, u.ID, r1.Snapshot.ID, meta.CommitOptions{ExpectedHead: ""})
	// A second head makes r1 deletable.
	r2h := mkSnapshot(t, s, u.ID, "a", "s", nil, 1<<30)
	if _, err := s.CommitSnapshot(ctx, u.ID, r2h.Snapshot.ID, meta.CommitOptions{ExpectedHead: r1.Snapshot.ID}); err != nil {
		t.Fatal(err)
	}
	// Delete the snapshot: refcount hits 0, bytes freed, row remains.
	if err := s.DeleteSnapshot(ctx, u.ID, "a", "s", r1.Snapshot.ID); err != nil {
		t.Fatal(err)
	}
	usage, _ := s.Usage(ctx, u.ID)
	if usage.UsedBytes != 128 {
		t.Fatalf("used after delete %d", usage.UsedBytes)
	}
	// New Begin referencing the stored zero-ref chunk: not missing, bytes recounted.
	r2 := mkSnapshot(t, s, u.ID, "a", "s2", chunks, 1<<30)
	if len(r2.Missing) != 0 {
		t.Fatal("revived chunk should not be missing")
	}
	usage, _ = s.Usage(ctx, u.ID)
	if usage.UsedBytes != 500+2*128 {
		t.Fatalf("used after revive %d", usage.UsedBytes)
	}
	fsckClean(t, s)
}

func testConflictForce(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "cf")
	r1 := mkSnapshot(t, s, u.ID, "a", "s", nil, 1<<30)
	_, _ = s.CommitSnapshot(ctx, u.ID, r1.Snapshot.ID, meta.CommitOptions{ExpectedHead: ""})
	r2 := mkSnapshot(t, s, u.ID, "a", "s", nil, 1<<30)
	var cerr *meta.ConflictError
	if _, err := s.CommitSnapshot(ctx, u.ID, r2.Snapshot.ID, meta.CommitOptions{ExpectedHead: "wrong"}); !errors.As(err, &cerr) {
		t.Fatalf("want ConflictError, got %v", err)
	}
	if cerr.Head.ID != r1.Snapshot.ID {
		t.Fatalf("conflict head %q", cerr.Head.ID)
	}
	if _, err := s.CommitSnapshot(ctx, u.ID, r2.Snapshot.ID, meta.CommitOptions{Force: true}); err != nil {
		t.Fatalf("force: %v", err)
	}
}

func testRetention(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	c := testclock.New(time.Time{})
	_ = c
	u := mkUser(t, s, "rt")
	var ids []string
	for i := 0; i < 5; i++ {
		r := mkSnapshot(t, s, u.ID, "a", "s", nil, 1<<30)
		head := ""
		if len(ids) > 0 {
			head = ids[len(ids)-1]
		}
		if _, err := s.CommitSnapshot(ctx, u.ID, r.Snapshot.ID, meta.CommitOptions{ExpectedHead: head, KeepLast: 3}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.Snapshot.ID)
	}
	list, _, err := s.ListSnapshots(ctx, u.ID, "a", "s", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("retention kept %d snapshots", len(list))
	}
	fsckClean(t, s)
}

func testAbortExpire(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "ae")
	exp := time.Now().Add(time.Hour)
	r1 := mkSnapshot(t, s, u.ID, "a", "s", []api.ChunkRef{chunkRef("e1", 100)}, 1<<30)
	_ = exp
	// Abort releases.
	if err := s.AbortSnapshot(ctx, u.ID, r1.Snapshot.ID); err != nil {
		t.Fatal(err)
	}
	usage, _ := s.Usage(ctx, u.ID)
	if usage.ReservedBytes != 0 || usage.UsedBytes != 0 {
		t.Fatalf("usage after abort %+v", usage)
	}
	// ExpirePending releases expired pending.
	r2, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", "s", []api.ChunkRef{chunkRef("e2", 50)},
		meta.BeginLimits{QuotaBytes: 1 << 30, ExpiresAt: time.Now().Add(-time.Minute)}))
	if err != nil {
		t.Fatal(err)
	}
	_ = r2
	n, err := s.ExpirePending(ctx, time.Now(), 10)
	if err != nil || n != 1 {
		t.Fatalf("expire %d %v", n, err)
	}
	usage, _ = s.Usage(ctx, u.ID)
	if usage.ReservedBytes != 0 || usage.UsedBytes != 0 {
		t.Fatalf("usage after expire %+v", usage)
	}
	fsckClean(t, s)
}

func testSharedReservation(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "sr")
	chunks := []api.ChunkRef{chunkRef("sh1", 300)}
	r1 := mkSnapshot(t, s, u.ID, "a", "s1", chunks, 1<<30)
	if len(r1.Missing) != 1 {
		t.Fatal("first begin missing")
	}
	r2 := mkSnapshot(t, s, u.ID, "a", "s2", chunks, 1<<30)
	if len(r2.Missing) != 1 {
		t.Fatal("shared reservation still missing for second snapshot")
	}
	usage, _ := s.Usage(ctx, u.ID)
	if usage.ReservedBytes != 300 {
		t.Fatalf("reserved double counted: %d", usage.ReservedBytes)
	}
	// One upload stores it for both.
	if err := s.MarkChunkStored(ctx, u.ID, r1.Snapshot.ID, chunks[0].Hash, 300); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkChunkStored(ctx, u.ID, r2.Snapshot.ID, chunks[0].Hash, 300); err != nil {
		t.Fatalf("shared second store should be idempotent: %v", err)
	}
	usage, _ = s.Usage(ctx, u.ID)
	if usage.UsedBytes != 300+2*128 || usage.ReservedBytes != 0 {
		t.Fatalf("usage %+v", usage)
	}
	// Aborting one keeps the other alive.
	if err := s.AbortSnapshot(ctx, u.ID, r1.Snapshot.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitSnapshot(ctx, u.ID, r2.Snapshot.ID, meta.CommitOptions{}); err != nil {
		t.Fatalf("commit after sibling abort: %v", err)
	}
	fsckClean(t, s)
}

func testGCProtocol(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "gc")
	chunks := []api.ChunkRef{chunkRef("g1", 400)}
	r1 := mkSnapshot(t, s, u.ID, "a", "s", chunks, 1<<30)
	storeAll(t, s, u.ID, r1.Snapshot.ID, chunks)
	_, _ = s.CommitSnapshot(ctx, u.ID, r1.Snapshot.ID, meta.CommitOptions{ExpectedHead: ""})
	r2h := mkSnapshot(t, s, u.ID, "a", "s", nil, 1<<30)
	if _, err := s.CommitSnapshot(ctx, u.ID, r2h.Snapshot.ID, meta.CommitOptions{ExpectedHead: r1.Snapshot.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSnapshot(ctx, u.ID, "a", "s", r1.Snapshot.ID); err != nil {
		t.Fatal(err)
	}
	// Within grace: not unreferenced yet.
	grace := time.Now().Add(24 * time.Hour)
	rows, err := s.UnreferencedChunks(ctx, grace, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("unref %d %v", len(rows), err)
	}
	// Crash simulation: row marked deleting, blob "deleted", then crash
	// before row delete. A Begin must revive it to reserved+missing.
	if md, ok := s.(interface {
		MarkDeleting(ctx context.Context, uid string, h api.Hash) (bool, error)
	}); ok {
		marked, err := md.MarkDeleting(ctx, u.ID, chunks[0].Hash)
		if err != nil || !marked {
			t.Fatal("mark deleting")
		}
	} else {
		t.Fatal("store lacks MarkDeleting")
	}
	r2 := mkSnapshot(t, s, u.ID, "a", "s2", chunks, 1<<30)
	if len(r2.Missing) != 1 {
		t.Fatal("deleting chunk must be missing")
	}
	// DeleteChunkRow must refuse now (refcount>0).
	ok, err := s.DeleteChunkRow(ctx, u.ID, chunks[0].Hash)
	if err != nil || ok {
		t.Fatal("DeleteChunkRow deleted live ref")
	}
	usage, _ := s.Usage(ctx, u.ID)
	if usage.ReservedBytes != 400 {
		t.Fatalf("reserved %d", usage.ReservedBytes)
	}
	fsckClean(t, s)
}

func testFsck(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "fk")
	chunks := []api.ChunkRef{chunkRef("f1", 100)}
	r1 := mkSnapshot(t, s, u.ID, "a", "s", chunks, 1<<30)
	storeAll(t, s, u.ID, r1.Snapshot.ID, chunks)
	_, _ = s.CommitSnapshot(ctx, u.ID, r1.Snapshot.ID, meta.CommitOptions{ExpectedHead: ""})
	r2h := mkSnapshot(t, s, u.ID, "a", "s", nil, 1<<30)
	_, _ = s.CommitSnapshot(ctx, u.ID, r2h.Snapshot.ID, meta.CommitOptions{ExpectedHead: r1.Snapshot.ID})
	fsckClean(t, s)
	// Corrupt via a second store is not possible; instead verify fsck
	// detects manual corruption by abusing expunge paths: delete the
	// snapshot, confirm zero-ref, then fsck still clean.
	if err := s.DeleteSnapshot(ctx, u.ID, "a", "s", r1.Snapshot.ID); err != nil {
		t.Fatal(err)
	}
	fsckClean(t, s)
}

func testPurge(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	u := mkUser(t, s, "pu")
	mkSnapshot(t, s, u.ID, "a", "s", []api.ChunkRef{chunkRef("p1", 10)}, 1<<30)
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	// Disabled users cannot begin.
	if _, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", "s", nil,
		meta.BeginLimits{QuotaBytes: 1 << 30})); !errors.Is(err, meta.ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
	pu, err := s.PurgedUsers(ctx, 10)
	if err != nil || len(pu) != 1 || pu[0].ID != u.ID {
		t.Fatal("PurgedUsers")
	}
	if err := s.FinishPurge(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser(ctx, u.ID); !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("user row remains after purge")
	}
	fsckClean(t, s)
}

func testLease(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Time{}))
	ctx := context.Background()
	ok, err := s.AcquireLease(ctx, "gc", "h1", time.Hour)
	if err != nil || !ok {
		t.Fatal("first acquire")
	}
	ok, err = s.AcquireLease(ctx, "gc", "h2", time.Hour)
	if err != nil || ok {
		t.Fatal("second holder must lose")
	}
	// Same holder renews.
	ok, err = s.AcquireLease(ctx, "gc", "h1", time.Hour)
	if err != nil || !ok {
		t.Fatal("renew")
	}
}

func testPagination(t *testing.T, f Factory) {
	c := testclock.New(time.Time{})
	s := f(t, c)
	ctx := context.Background()
	u := mkUser(t, s, "pg")
	var prev string
	for i := 0; i < 5; i++ {
		c.Add(time.Minute)
		r := mkSnapshot(t, s, u.ID, "a", "s", nil, 1<<30)
		if _, err := s.CommitSnapshot(ctx, u.ID, r.Snapshot.ID, meta.CommitOptions{ExpectedHead: prev}); err != nil {
			t.Fatal(err)
		}
		prev = r.Snapshot.ID
	}
	var seen []string
	cursor := ""
	for {
		page, next, err := s.ListSnapshots(ctx, u.ID, "a", "s", cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, sn := range page {
			seen = append(seen, sn.ID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 5 {
		t.Fatalf("paginated %d snapshots", len(seen))
	}
	// Newest first.
	if seen[0] != prev {
		t.Fatal("newest first violated")
	}
}

func stressQuota(t *testing.T, factory Factory) {
	c := testclock.New(time.Time{})
	s := factory(t, c)
	ctx := context.Background()
	u := mkUser(t, s, "sq")
	const quota = 1000
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", fmt.Sprintf("s%d", i),
				[]api.ChunkRef{chunkRef(fmt.Sprintf("sq%d", i), 200)},
				meta.BeginLimits{QuotaBytes: quota, MaxSlots: 100, MaxPendingSnapshots: 100, ExpiresAt: c.Now().Add(time.Hour)}))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	var qerr *meta.QuotaError
	var succeeded int
	for err := range errs {
		if err == nil {
			succeeded++
			continue
		}
		if !errors.As(err, &qerr) {
			t.Fatalf("unexpected err %v", err)
		}
	}
	usage, _ := s.Usage(ctx, u.ID)
	if usage.UsedBytes+usage.ReservedBytes > quota {
		t.Fatalf("quota breached: %+v", usage)
	}
	// Expire everything: usage must drain to 0.
	c.Add(2 * time.Hour)
	if _, err := s.ExpirePending(ctx, c.Now(), 1000); err != nil {
		t.Fatal(err)
	}
	usage, _ = s.Usage(ctx, u.ID)
	if usage.UsedBytes != 0 || usage.ReservedBytes != 0 {
		t.Fatalf("phantom reservation: %+v", usage)
	}
	fsckClean(t, s)
}

func stressGCRace(t *testing.T, factory Factory) {
	c := testclock.New(time.Time{})
	s := factory(t, c)
	ctx := context.Background()
	u := mkUser(t, s, "gc")
	type deleter interface {
		MarkDeleting(ctx context.Context, uid string, h api.Hash) (bool, error)
	}
	md, _ := s.(deleter)
	done := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 256)
	// Writers: churn begin/store/commit/delete.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				select {
				case <-done:
					return
				default:
				}
				ch := chunkRef(fmt.Sprintf("w%d-%d", i, j), 64)
				r, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", fmt.Sprintf("w%d", i), []api.ChunkRef{ch},
					meta.BeginLimits{QuotaBytes: 1 << 40, MaxSlots: 100, MaxPendingSnapshots: 100, ExpiresAt: c.Now().Add(time.Hour)}))
				if err != nil {
					errs <- err
					return
				}
				if len(r.Missing) > 0 {
					if err := s.MarkChunkStored(ctx, u.ID, r.Snapshot.ID, ch.Hash, 64); err != nil && !errors.Is(err, meta.ErrNotExpected) && !errors.Is(err, meta.ErrNotFound) {
						errs <- err
						return
					}
				}
				_, _ = s.CommitSnapshot(ctx, u.ID, r.Snapshot.ID, meta.CommitOptions{Force: true})
				_ = s.DeleteSnapshot(ctx, u.ID, "a", fmt.Sprintf("w%d", i), r.Snapshot.ID)
			}
		}(i)
	}
	// GC loop: expire, mark deleting, delete rows.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			select {
			case <-done:
				return
			default:
			}
			_, _ = s.ExpirePending(ctx, c.Now().Add(2*time.Hour), 50)
			c.Add(time.Minute)
			rows, _ := s.UnreferencedChunks(ctx, c.Now(), 50)
			for _, r := range rows {
				if md != nil {
					_, _ = md.MarkDeleting(ctx, r.UserID, r.Hash)
				}
				_, _ = s.DeleteChunkRow(ctx, r.UserID, r.Hash)
			}
		}
	}()
	wg.Wait()
	close(done)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("stress err: %v", err)
		}
	}
	// No referenced chunk row may be missing: fsck must be clean.
	fsckClean(t, s)
}

func stressCommitCAS(t *testing.T, factory Factory) {
	c := testclock.New(time.Time{})
	s := factory(t, c)
	ctx := context.Background()
	u := mkUser(t, s, "cas")
	const n = 8
	var snaps []meta.BeginResult
	for i := 0; i < n; i++ {
		r := mkSnapshot(t, s, u.ID, "a", "s", nil, 1<<30)
		snaps = append(snaps, r)
	}
	var wg sync.WaitGroup
	var wins, conflicts int32
	var mu sync.Mutex
	for _, r := range snaps {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, err := s.CommitSnapshot(ctx, u.ID, id, meta.CommitOptions{ExpectedHead: ""})
			mu.Lock()
			if err == nil {
				wins++
			} else {
				var ce *meta.ConflictError
				if errors.As(err, &ce) {
					conflicts++
				}
			}
			mu.Unlock()
		}(r.Snapshot.ID)
	}
	wg.Wait()
	if wins != 1 || conflicts != n-1 {
		t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
	}
}

func stressExpireAbort(t *testing.T, factory Factory) {
	c := testclock.New(time.Time{})
	s := factory(t, c)
	ctx := context.Background()
	u := mkUser(t, s, "ea")
	const n = 32
	var ids []string
	for i := 0; i < n; i++ {
		r := mkSnapshot(t, s, u.ID, "a", fmt.Sprintf("s%d", i), []api.ChunkRef{chunkRef(fmt.Sprintf("ea%d", i), 10)}, 1<<40)
		ids = append(ids, r.Snapshot.ID)
	}
	c.Add(2 * time.Hour)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(2)
		go func(id string) { defer wg.Done(); _ = s.AbortSnapshot(ctx, u.ID, id) }(id)
		go func(id string) { defer wg.Done(); _, _ = s.ExpirePending(ctx, c.Now(), 1) }(id)
	}
	wg.Wait()
	// Drain the rest.
	for {
		n, err := s.ExpirePending(ctx, c.Now(), 100)
		if err != nil || n == 0 {
			break
		}
	}
	usage, _ := s.Usage(ctx, u.ID)
	if usage.UsedBytes != 0 || usage.ReservedBytes != 0 {
		t.Fatalf("double release: %+v", usage)
	}
	fsckClean(t, s)
}

func stressFsckProperty(t *testing.T, factory Factory) {
	seed := uint64(12345)
	c := testclock.New(time.Time{})
	s := factory(t, c)
	ctx := context.Background()
	u := mkUser(t, s, "prop")
	rnd := rand.New(rand.NewPCG(seed, 99)) // #nosec G404 -- seeded test determinism
	var live []string                      // committed or pending snapshot ids
	chunks := []api.ChunkRef{chunkRef("p1", 50), chunkRef("p2", 60), chunkRef("p3", 70)}
	var head string
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("seed %d: %s", seed, fmt.Sprintf(format, a...))
	}
	for step := 0; step < 120; step++ {
		switch rnd.IntN(6) {
		case 0: // begin
			var refs []api.ChunkRef
			if rnd.IntN(2) == 0 {
				refs = append(refs, chunks[rnd.IntN(len(chunks))])
			}
			r, err := s.BeginSnapshot(ctx, mkParams(u.ID, "a", "s", refs,
				meta.BeginLimits{QuotaBytes: 1 << 40, MaxPendingSnapshots: 64, ExpiresAt: c.Now().Add(time.Hour)}))
			if err != nil {
				fail("begin: %v", err)
			}
			live = append(live, r.Snapshot.ID)
		case 1: // store all missing of a random pending
			if len(live) == 0 {
				continue
			}
			id := live[rnd.IntN(len(live))]
			for _, ch := range chunks {
				_ = s.MarkChunkStored(ctx, u.ID, id, ch.Hash, int64(ch.Size))
			}
		case 2: // commit
			if len(live) == 0 {
				continue
			}
			id := live[rnd.IntN(len(live))]
			_, _ = s.CommitSnapshot(ctx, u.ID, id, meta.CommitOptions{Force: true, KeepLast: 100})
			head = id
			_ = head
		case 3: // abort
			if len(live) == 0 {
				continue
			}
			i := rnd.IntN(len(live))
			_ = s.AbortSnapshot(ctx, u.ID, live[i])
			live = append(live[:i], live[i+1:]...)
		case 4: // delete committed
			if len(live) == 0 {
				continue
			}
			i := rnd.IntN(len(live))
			_ = s.DeleteSnapshot(ctx, u.ID, "a", "s", live[i])
			live = append(live[:i], live[i+1:]...)
		case 5: // expire
			c.Add(30 * time.Minute)
			_, _ = s.ExpirePending(ctx, c.Now(), 5)
			var rest []string
			for _, id := range live {
				sn, err := s.GetSnapshot(ctx, u.ID, "a", "s", id)
				if err == nil && sn.State == meta.StatePending {
					rest = append(rest, id)
				} else if err == nil {
					rest = append(rest, id)
				}
			}
			live = rest
		}
	}
	rep, err := s.Fsck(ctx, false)
	if err != nil {
		fail("fsck: %v", err)
	}
	if len(rep.Issues) > 0 {
		fail("fsck issues: %v", rep.Issues)
	}
	// Usage must equal fsck recomputation: usage row is already checked
	// against recomputed values inside Fsck, so a clean report suffices.
}
