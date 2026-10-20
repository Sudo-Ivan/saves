// SPDX-License-Identifier: 0BSD

package service

import (
	"bytes"
	"context"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

type countBlob struct {
	blob.Store
	opens int
}

func (c *countBlob) Open(ctx context.Context, key string) (blob.Object, error) {
	c.opens++
	return c.Store.Open(ctx, key)
}

func TestManifestCache(t *testing.T) {
	s, m, b, _ := setup(t)
	ctx := context.Background()
	p := principal(t, m, "mc", auth.ScopeRead|auth.ScopeWrite)
	cb := &countBlob{Store: b}
	s.Blob = cb
	s.manCache = newManifestCache(64 << 20)
	data := bytes.Repeat([]byte{4}, 4096)
	h := api.HashBytes(data)
	man := manifest(api.File{Path: "f", Size: int64(len(data)),
		Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(data))}}})
	out, err := s.BeginSnapshot(ctx, p, "a", "sl", "", "", "", man)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutChunk(ctx, p, "a", "sl", out.ID, h, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitSnapshot(ctx, p, "a", "sl", out.ID, "", false); err != nil {
		t.Fatal(err)
	}
	before := cb.opens
	for i := 0; i < 3; i++ {
		fh, err := s.OpenFile(ctx, p, "a", "sl", out.ID, "f")
		if err != nil {
			t.Fatal(err)
		}
		if c, ok := fh.Reader.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
	delta := cb.opens - before
	// second+ opens must not re-read the manifest blob (one manifest open max,
	// chunk opens allowed)
	if delta > 4 {
		t.Fatalf("opens %d, expected <= 4", delta)
	}
	// disabled cache re-reads
	cb2 := &countBlob{Store: b}
	s.Blob = cb2
	s.manCache = nil
	for i := 0; i < 2; i++ {
		if _, err := s.OpenFile(ctx, p, "a", "sl", out.ID, "f"); err != nil {
			t.Fatal(err)
		}
	}
	// cross-user: B asking for A's manifest hash does not get A's manifest
	p2 := principal(t, m, "mc2", auth.ScopeRead|auth.ScopeWrite)
	if _, _, err := s.GetManifest(ctx, p2, "a", "sl", out.ID); err == nil {
		t.Fatal("cross-user manifest leak")
	}
}

func TestManifestCacheEvict(t *testing.T) {
	c := newManifestCache(4096)
	var h api.Hash
	m1 := api.Manifest{Version: 1, Files: []api.File{{Path: "a"}}}
	m2 := api.Manifest{Version: 1, Files: []api.File{{Path: "b"}}}
	copy(h[:], []byte("k1"))
	c.put("u", h, m1, bytes.Repeat([]byte{1}, 3500))
	var h2 api.Hash
	copy(h2[:], []byte("k2"))
	c.put("u", h2, m2, bytes.Repeat([]byte{1}, 3500))
	if _, _, ok := c.get("u", h); ok {
		t.Fatal("expected eviction")
	}
}
