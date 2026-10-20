// SPDX-License-Identifier: 0BSD

package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/metatest"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func factory(t *testing.T, c *testclock.Clock) meta.Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "meta.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestConformance(t *testing.T) {
	metatest.Run(t, factory)
}

func TestVault(t *testing.T) {
	st := factory(t, testclock.New(time.Now()))
	defer st.Close()
	metatest.VaultRoundTrip(t, st)
}

func BenchmarkBegin100(b *testing.B) {
	benchBegin(b, 100)
}

func BenchmarkBegin2000(b *testing.B) {
	benchBegin(b, 2000)
}

func benchBegin(b *testing.B, n int) {
	c := testclock.New(time.Now())
	s, err := Open(filepath.Join(b.TempDir(), "meta.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	u, _, err := s.UpsertUser(context.Background(), "bench", "free")
	if err != nil {
		b.Fatal(err)
	}
	chunks := make([]api.ChunkRef, n)
	var seed [8]byte
	for i := range chunks {
		seed[0] = byte(i)
		seed[1] = byte(i >> 8)
		chunks[i] = api.ChunkRef{Hash: api.HashBytes(seed[:]), Size: 1024}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range chunks {
			chunks[j].Hash[0] = byte(i)
		}
		_, err := s.BeginSnapshot(b.Context(), meta.BeginParams{
			UserID: u.ID, App: "a", Slot: "s", ManifestHash: api.HashBytes([]byte{byte(i)}),
			ManifestSize: 128, Chunks: chunks,
			Limits: meta.BeginLimits{QuotaBytes: 1 << 60, MaxSlots: 1000, MaxPendingSnapshots: 1 << 20,
				ExpiresAt: time.Now().Add(time.Hour)},
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarkChunkStored(b *testing.B) {
	c := testclock.New(time.Now())
	s, err := Open(filepath.Join(b.TempDir(), "meta.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	u, _, _ := s.UpsertUser(context.Background(), "bench", "free")
	r, err := s.BeginSnapshot(context.Background(), meta.BeginParams{
		UserID: u.ID, App: "a", Slot: "s", ManifestHash: api.HashBytes([]byte("m")),
		ManifestSize: 128, Chunks: []api.ChunkRef{{Hash: api.HashBytes([]byte("c")), Size: 100}},
		Limits: meta.BeginLimits{QuotaBytes: 1 << 40, ExpiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		b.Fatal(err)
	}
	h := api.HashBytes([]byte("c"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Stored chunks with a live ref are idempotent success.
		if err := s.MarkChunkStored(b.Context(), u.ID, r.Snapshot.ID, h, 100); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCommit(b *testing.B) {
	c := testclock.New(time.Now())
	s, err := Open(filepath.Join(b.TempDir(), "meta.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	u, _, _ := s.UpsertUser(context.Background(), "bench", "free")
	head := ""
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := mkFullB(b, s, u.ID, i)
		res, err := s.CommitSnapshot(b.Context(), u.ID, r.Snapshot.ID, meta.CommitOptions{ExpectedHead: head, Force: head == ""})
		if err != nil {
			b.Fatal(err)
		}
		head = res.Snapshot.ID
	}
}

func mkFullB(b *testing.B, s meta.Store, uid string, i int) meta.BeginResult {
	h := api.HashBytes([]byte{byte(i), byte(i >> 8)})
	r, err := s.BeginSnapshot(context.Background(), meta.BeginParams{
		UserID: uid, App: "a", Slot: "s", ManifestHash: h, ManifestSize: 10,
		Limits: meta.BeginLimits{QuotaBytes: 1 << 40, ExpiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		b.Fatal(err)
	}
	return r
}

func BenchmarkTokenLookup(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "meta.db"), meta.Options{})
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	u, _, _ := s.UpsertUser(context.Background(), "bench", "free")
	var sh [32]byte
	if err := s.CreateToken(context.Background(), meta.Token{ID: "0123456789abcdef", UserID: u.ID, SecretHash: sh}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.GetToken(b.Context(), "0123456789abcdef"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
