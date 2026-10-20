// SPDX-License-Identifier: 0BSD

package meta_test

import (
	"context"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/pkg/api"
	"path/filepath"
	"time"
)

func FuzzCursor(f *testing.F) {
	f.Add("")
	f.Add("AAAA")
	f.Fuzz(func(t *testing.T, c string) {
		_, _, _ = meta.DecodeCursor(c)
	})
}

// FuzzMetaOps decodes a random op sequence and applies it to a fresh
// sqlite store, checking Fsck stays clean and quota is never exceeded.
func FuzzMetaOps(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Fuzz(func(t *testing.T, ops []byte) {
		dir := t.TempDir()
		s, err := sqlite.Open(filepath.Join(dir, "m.db"), meta.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		u, _, err := s.UpsertUser(ctx, "fz", "free")
		if err != nil {
			t.Fatal(err)
		}
		const quota = 4096
		var snaps []string
		for i, b := range ops {
			var chunks []api.ChunkRef
			if b&0x80 != 0 {
				chunks = append(chunks, api.ChunkRef{Hash: api.HashBytes([]byte{byte(i)}), Size: uint32(b&0x7f) + 1})
			}
			switch b % 6 {
			case 0: // begin
				r, err := s.BeginSnapshot(ctx, meta.BeginParams{
					UserID: u.ID, App: "a", Slot: "s", ManifestHash: api.HashBytes([]byte{byte(i), 1}),
					ManifestSize: 10, Chunks: chunks,
					Limits: meta.BeginLimits{QuotaBytes: quota, MaxSlots: 64, MaxPendingSnapshots: 64},
				})
				if err == nil {
					snaps = append(snaps, r.Snapshot.ID)
				}
			case 1: // store
				if len(snaps) > 0 && len(chunks) > 0 {
					s.MarkChunkStored(ctx, u.ID, snaps[len(snaps)-1], chunks[0].Hash, int64(chunks[0].Size))
				}
			case 2: // commit
				if len(snaps) > 0 {
					s.CommitSnapshot(ctx, u.ID, snaps[len(snaps)-1], meta.CommitOptions{Force: true})
				}
			case 3: // abort
				if len(snaps) > 0 {
					id := snaps[len(snaps)-1]
					snaps = snaps[:len(snaps)-1]
					s.AbortSnapshot(ctx, u.ID, id)
				}
			case 4: // delete
				if len(snaps) > 0 {
					id := snaps[0]
					snaps = snaps[1:]
					s.DeleteSnapshot(ctx, u.ID, "a", "s", id)
				}
			case 5: // expire
				s.ExpirePending(ctx, time.Now(), 10)
			}
			u2, err := s.Usage(ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if u2.UsedBytes+u2.ReservedBytes > quota {
				t.Fatalf("quota exceeded: %+v", u2)
			}
		}
		rep, err := s.Fsck(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Issues) > 0 {
			t.Fatalf("fsck issues: %v", rep.Issues)
		}
	})
}
