package service

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func TestRangeProbe(t *testing.T) {
	s, m, _, _ := setup(t)
	ctx := context.Background()
	p := principal(t, m, "probe", auth.ScopeRead|auth.ScopeWrite)
	const n = 64 << 20
	var refs []api.ChunkRef
	var parts [][]byte
	for off := 0; off < n; off += 2 << 20 {
		c := bytes.Repeat([]byte{byte(off >> 20)}, 2<<20)
		parts = append(parts, c)
		refs = append(refs, api.ChunkRef{Hash: api.HashBytes(c), Size: 2 << 20})
	}
	man := manifest(api.File{Path: "big", Size: n, Chunks: refs})
	out, err := s.BeginSnapshot(ctx, p, "app", "slot", "", "", "", man)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range refs {
		if err := s.PutChunk(ctx, p, "app", "slot", out.ID, r.Hash, bytes.NewReader(parts[i]), int64(len(parts[i]))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CommitSnapshot(ctx, p, "app", "slot", out.ID, "", false); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4<<20)
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		fh, err := s.OpenFile(ctx, p, "app", "slot", out.ID, "big")
		tOpen := time.Since(t0)
		if err != nil {
			t.Fatal(err)
		}
		t1 := time.Now()
		nn, err := fh.Reader.(io.ReaderAt).ReadAt(buf, int64(i)*4<<20)
		tRead := time.Since(t1)
		t.Logf("open=%v read=%v n=%d err=%v", tOpen, tRead, nn, err)
	}
}
