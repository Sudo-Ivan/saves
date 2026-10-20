// SPDX-License-Identifier: 0BSD

package service

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/blob/mem"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/gc"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/Sudo-Ivan/saves/internal/quota"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func setup(t *testing.T) (*Service, meta.Store, *mem.Store, *testclock.Clock) {
	t.Helper()
	c := testclock.New(time.Now())
	m, err := sqlite.Open(filepath.Join(t.TempDir(), "m.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := mem.New()
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	q := quota.New(&cfg)
	s := New(m, b, q, Options{Clock: c.NowFunc(), MaxConcurrentUploadsPerUser: 16})
	t.Cleanup(func() { m.Close() })
	return s, m, b, c
}

func principal(t *testing.T, m meta.Store, subject string, scopes auth.Scope) auth.Principal {
	t.Helper()
	u, _, err := m.UpsertUser(context.Background(), subject, "free")
	if err != nil {
		t.Fatal(err)
	}
	return auth.Principal{User: u, Scopes: scopes}
}

func manifest(files ...api.File) api.Manifest {
	return api.Manifest{Version: 1, Files: files}
}

func TestEndToEnd(t *testing.T) {
	s, m, b, c := setup(t)
	ctx := context.Background()
	p := principal(t, m, "e2e", auth.ScopeRead|auth.ScopeWrite)

	data1 := bytes.Repeat([]byte("A"), 300<<10)
	data2 := bytes.Repeat([]byte("B"), 150<<10)
	h1 := api.HashBytes(data1)
	h2 := api.HashBytes(data2)
	man := manifest(
		api.File{Path: "a.bin", Size: int64(len(data1)), Mode: 0o644, ModTimeNS: 1000, Chunks: []api.ChunkRef{{Hash: h1, Size: uint32(len(data1))}}},
		api.File{Path: "b.bin", Size: int64(len(data2)), Mode: 0o644, ModTimeNS: 2000, Chunks: []api.ChunkRef{{Hash: h2, Size: uint32(len(data2))}}},
	)
	out, err := s.BeginSnapshot(ctx, p, "app", "slot", "dev", "lbl", "", man)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Missing) != 2 {
		t.Fatalf("missing %v", out.Missing)
	}
	for _, h := range out.Missing {
		data := data1
		if h == h2 {
			data = data2
		}
		if err := s.PutChunk(ctx, p, "app", "slot", out.ID, h, bytes.NewReader(data), int64(len(data))); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.CommitSnapshot(ctx, p, "app", "slot", out.ID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	// Second begin with same data dedupes fully.
	out2, err := s.BeginSnapshot(ctx, p, "app", "slot", "dev", "lbl", res.Snapshot.ID, man)
	if err != nil {
		t.Fatal(err)
	}
	if len(out2.Missing) != 0 {
		t.Fatalf("dedup failed: %v", out2.Missing)
	}
	// Ranged read across the chunk.
	fh, err := s.OpenFile(ctx, p, "app", "slot", out.ID, "a.bin")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err := fh.Reader.(io.ReaderAt).ReadAt(buf, int64(len(data1))-50)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], data1[len(data1)-50:]) {
		t.Fatal("range read mismatch")
	}
	if fh.Size != int64(len(data1)) {
		t.Fatal("size")
	}
	// Archive contents.
	var tb bytes.Buffer
	if err := s.WriteArchive(ctx, p, "app", "slot", out.ID, &tb); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&tb)
	var got int
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got++
		if h.Name == "a.bin" {
			d, _ := io.ReadAll(tr)
			if !bytes.Equal(d, data1) {
				t.Fatal("archive a.bin mismatch")
			}
		}
	}
	if got != 2 {
		t.Fatalf("archive entries %d", got)
	}
	// GC after deleting slot and advancing past grace.
	if err := s.DeleteSlot(ctx, p, "app", "slot"); err != nil {
		t.Fatal(err)
	}
	c.Add(48 * time.Hour)
	g := gc.New(m, b, gc.Options{Grace: time.Hour, Holder: "test", Clock: c.NowFunc()})
	rep, err := g.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ChunksDeleted != 2 || rep.ManifestsDeleted != 1 {
		t.Fatalf("gc report %+v", rep)
	}
	var keys int
	_ = b.List(ctx, "", func(e blob.Entry) error { keys++; return nil })
	if keys != 0 {
		t.Fatalf("%d blobs remain", keys)
	}
	frep, _ := m.Fsck(ctx, false)
	if len(frep.Issues) > 0 {
		t.Fatalf("fsck: %v", frep.Issues)
	}
}

func TestIsolation(t *testing.T) {
	s, m, _, _ := setup(t)
	ctx := context.Background()
	a := principal(t, m, "ua", auth.ScopeRead|auth.ScopeWrite)
	b := principal(t, m, "ub", auth.ScopeRead|auth.ScopeWrite)
	h := api.HashBytes([]byte("secret"))
	man := manifest(api.File{Path: "s", Size: 6, Mode: 0o644, Chunks: []api.ChunkRef{{Hash: h, Size: 6}}})
	out, err := s.BeginSnapshot(ctx, a, "app", "slot", "", "", "", man)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutChunk(ctx, a, "app", "slot", out.ID, h, bytes.NewReader([]byte("secret")), 6); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitSnapshot(ctx, a, "app", "slot", out.ID, "", false); err != nil {
		t.Fatal(err)
	}
	// B cannot see A's slot, snapshot, manifest, chunk.
	if _, err := s.GetSlot(ctx, b, "app", "slot"); !isNotFound(err) {
		t.Fatalf("slot leak: %v", err)
	}
	if _, _, err := s.GetManifest(ctx, b, "app", "slot", out.ID); !isNotFound(err) {
		t.Fatalf("manifest leak: %v", err)
	}
	if _, err := s.OpenChunk(ctx, b, "app", h); !isNotFound(err) {
		t.Fatalf("chunk leak: %v", err)
	}
	if _, err := s.ResolveSnapshot(ctx, b, "app", "slot", "latest"); !isNotFound(err) {
		t.Fatalf("snapshot leak: %v", err)
	}
}

func TestScopes(t *testing.T) {
	s, m, _, _ := setup(t)
	ctx := context.Background()
	ro := principal(t, m, "ro", auth.ScopeRead)
	_, err := s.BeginSnapshot(ctx, ro, "app", "slot", "", "", "", manifest())
	var prob *api.Problem
	if !errors.As(err, &prob) || prob.Status != 403 {
		t.Fatalf("want 403, got %v", err)
	}
	// App allowlist.
	u, _, _ := m.UpsertUser(ctx, "limited", "free")
	lp := auth.Principal{User: u, Scopes: auth.ScopeRead | auth.ScopeWrite, Apps: []string{"ok"}}
	if _, err := s.BeginSnapshot(ctx, lp, "other", "slot", "", "", "", manifest()); !errors.As(err, &prob) || prob.Status != 403 {
		t.Fatalf("app allowlist: %v", err)
	}
}

func TestQuotaMidway(t *testing.T) {
	s, m, _, _ := setup(t)
	ctx := context.Background()
	p := principal(t, m, "q", auth.ScopeRead|auth.ScopeWrite)
	q := meta.Optional[int64]{Set: true, Value: 100}
	if _, err := m.UpdateUser(ctx, p.User.ID, meta.UserPatch{QuotaBytes: &q}); err != nil {
		t.Fatal(err)
	}
	h := api.HashBytes([]byte("big"))
	man := manifest(api.File{Path: "x", Size: 500, Chunks: []api.ChunkRef{{Hash: h, Size: 500}}})
	_, err := s.BeginSnapshot(ctx, p, "app", "slot", "", "", "", man)
	var qe *meta.QuotaError
	var prob *api.Problem
	if !errors.As(err, &qe) && !errors.As(err, &prob) {
		t.Fatalf("want quota error, got %v", err)
	}
}

func TestConflictForce(t *testing.T) {
	s, m, _, _ := setup(t)
	ctx := context.Background()
	p := principal(t, m, "cf", auth.ScopeRead|auth.ScopeWrite)
	man := manifest()
	out1, _ := s.BeginSnapshot(ctx, p, "app", "slot", "", "", "", man)
	if _, err := s.CommitSnapshot(ctx, p, "app", "slot", out1.ID, "", false); err != nil {
		t.Fatal(err)
	}
	out2, _ := s.BeginSnapshot(ctx, p, "app", "slot", "", "", "", man)
	if _, err := s.CommitSnapshot(ctx, p, "app", "slot", out2.ID, "wrong-head", false); err == nil {
		t.Fatal("want conflict")
	}
	if _, err := s.CommitSnapshot(ctx, p, "app", "slot", out2.ID, out1.ID, false); err != nil {
		t.Fatalf("correct head: %v", err)
	}
}

func isNotFound(err error) bool {
	var p *api.Problem
	return errors.As(err, &p) && p.Status == 404
}

func TestParallelPut(t *testing.T) {
	s, m, _, _ := setup(t)
	ctx := context.Background()
	p := principal(t, m, "pp", auth.ScopeRead|auth.ScopeWrite)
	h := api.HashBytes([]byte("chunk"))
	man := manifest(api.File{Path: "f", Size: 5, Chunks: []api.ChunkRef{{Hash: h, Size: 5}}})
	out, err := s.BeginSnapshot(ctx, p, "app", "slot", "", "", "", man)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			done <- s.PutChunk(ctx, p, "app", "slot", out.ID, h, bytes.NewReader([]byte("chunk")), 5)
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if _, err := s.CommitSnapshot(ctx, p, "app", "slot", out.ID, "", false); err != nil {
		t.Fatal(err)
	}
	usage, _ := m.Usage(ctx, p.User.ID)
	if usage.UsedBytes != 5+manifestSize() {
		t.Fatalf("used %d", usage.UsedBytes)
	}
}

func manifestSize() int64 {
	m := manifest(api.File{Path: "f", Size: 5, Chunks: []api.ChunkRef{{Hash: api.HashBytes([]byte("chunk")), Size: 5}}})
	b, _, err := m.Canonical()
	if err != nil {
		return 0
	}
	return int64(len(b))
}

func BenchmarkPutChunk1MiB(b *testing.B) {
	c := testclock.New(time.Now())
	m, err := sqlite.Open(filepath.Join(b.TempDir(), "m.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		b.Fatal(err)
	}
	if err := m.Migrate(context.Background()); err != nil {
		b.Fatal(err)
	}
	defer m.Close()
	mb := mem.New()
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	s := New(m, mb, quota.New(&cfg), Options{Clock: c.NowFunc(), MaxConcurrentUploadsPerUser: 16})
	u, _, _ := m.UpsertUser(context.Background(), "bench", "free")
	p := auth.Principal{User: u, Scopes: auth.ScopeRead | auth.ScopeWrite}
	data := bytes.Repeat([]byte{1}, 1<<20)
	h := api.HashBytes(data)
	man := manifest(api.File{Path: "f", Size: int64(len(data)), Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(data))}}})
	out, err := s.BeginSnapshot(context.Background(), p, "app", "slot", "", "", "", man)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.PutChunk(b.Context(), p, "app", "slot", out.ID, h, bytes.NewReader(data), int64(len(data))); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenFileReadAt(b *testing.B) {
	c := testclock.New(time.Now())
	m, err := sqlite.Open(filepath.Join(b.TempDir(), "m.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		b.Fatal(err)
	}
	if err := m.Migrate(context.Background()); err != nil {
		b.Fatal(err)
	}
	defer m.Close()
	mb := mem.New()
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	s := New(m, mb, quota.New(&cfg), Options{Clock: c.NowFunc()})
	u, _, _ := m.UpsertUser(context.Background(), "bench", "free")
	p := auth.Principal{User: u, Scopes: auth.ScopeRead | auth.ScopeWrite}
	var refs []api.ChunkRef
	var chunks [][]byte
	for i := 0; i < 16; i++ {
		d := bytes.Repeat([]byte{byte(i)}, 256<<10)
		h := api.HashBytes(d)
		chunks = append(chunks, d)
		refs = append(refs, api.ChunkRef{Hash: h, Size: uint32(len(d))})
	}
	man := manifest(api.File{Path: "f", Size: 16 * 256 << 10, Chunks: refs})
	out, err := s.BeginSnapshot(context.Background(), p, "app", "slot", "", "", "", man)
	if err != nil {
		b.Fatal(err)
	}
	for i, r := range refs {
		if err := s.PutChunk(context.Background(), p, "app", "slot", out.ID, r.Hash, bytes.NewReader(chunks[i]), int64(len(chunks[i]))); err != nil {
			b.Fatal(err)
		}
	}
	if _, err := s.CommitSnapshot(context.Background(), p, "app", "slot", out.ID, "", false); err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fh, err := s.OpenFile(b.Context(), p, "app", "slot", out.ID, "f")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := fh.Reader.(io.ReaderAt).ReadAt(buf, int64(i%200)*4096); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}
