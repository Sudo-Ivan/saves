// SPDX-License-Identifier: 0BSD

package chunkindex

import (
	"bytes"
	"io"
	"testing"

	"context"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/blob/mem"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func store(t testing.TB, chunks [][]byte) (*mem.Store, []api.ChunkRef) {
	t.Helper()
	b := mem.New()
	var refs []api.ChunkRef
	for _, c := range chunks {
		h := api.HashBytes(c)
		if err := b.Put(context.Background(), blob.ChunkKey("u", h), bytes.NewReader(c), int64(len(c)), &h); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, api.ChunkRef{Hash: h, Size: uint32(len(c))})
	}
	return b, refs
}

func TestReadAt(t *testing.T) {
	data := []byte("0123456789")
	b, refs := store(t, [][]byte{data[:3], data[3:7], data[7:]})
	open := func(h api.Hash) (blob.Object, error) {
		return b.Open(context.Background(), blob.ChunkKey("u", h))
	}
	r, err := New(refs, 10, open)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	buf := make([]byte, 10)
	if n, err := r.ReadAt(buf, 0); err != nil || n != 10 || !bytes.Equal(buf, data) {
		t.Fatalf("full read %v", err)
	}
	if n, err := r.ReadAt(buf[:3], 8); err != io.EOF || n != 2 || string(buf[:2]) != "89" {
		t.Fatalf("edge read %v", err)
	}
	if _, err := r.ReadAt(buf, 10); err != io.EOF {
		t.Fatalf("past end %v", err)
	}
	// Seek+Read.
	if _, err := r.Seek(4, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	if string(got) != "456789" {
		t.Fatalf("seek read %q", got)
	}
	// Mismatched size rejected.
	if _, err := New(refs, 11, open); err == nil {
		t.Fatal("bad size accepted")
	}
}

func FuzzChunkedReaderReadAt(f *testing.F) {
	f.Add([]byte{3, 5, 2, 0, 4})
	f.Fuzz(func(t *testing.T, sizes []byte) {
		var chunks [][]byte
		var full []byte
		for i, s := range sizes {
			n := int(s) % 32
			c := bytes.Repeat([]byte{byte(i)}, n)
			chunks = append(chunks, c)
			full = append(full, c...)
		}
		b, refs := store(t, chunks)
		open := func(h api.Hash) (blob.Object, error) {
			return b.Open(context.Background(), blob.ChunkKey("u", h))
		}
		r, err := New(refs, int64(len(full)), open)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		want := bytes.NewReader(full)
		// Random reads from the fuzz bytes.
		for i, s := range sizes {
			off := int64(int(s) * int(i+1) % (len(full) + 1))
			ln := int(s) % 64
			got := make([]byte, ln)
			exp := make([]byte, ln)
			en, eerr := want.ReadAt(exp, off)
			gn, gerr := r.ReadAt(got, off)
			if en != gn || (eerr == nil) != (gerr == nil) || !bytes.Equal(exp[:en], got[:gn]) {
				t.Fatalf("off %d len %d: got %d/%v want %d/%v", off, ln, gn, gerr, en, eerr)
			}
		}
	})
}

func BenchmarkReadAtSequential(b *testing.B) {
	var chunks [][]byte
	for i := 0; i < 64; i++ {
		chunks = append(chunks, bytes.Repeat([]byte{byte(i)}, 64<<10))
	}
	st, refs := store(b, chunks)
	open := func(h api.Hash) (blob.Object, error) {
		return st.Open(context.Background(), blob.ChunkKey("u", h))
	}
	r, _ := New(refs, 64*64<<10, open)
	defer r.Close()
	buf := make([]byte, 64<<10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		off := int64(i%64) * (64 << 10)
		if _, err := r.ReadAt(buf, off); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadAtRandom(b *testing.B) {
	var chunks [][]byte
	for i := 0; i < 64; i++ {
		chunks = append(chunks, bytes.Repeat([]byte{byte(i)}, 64<<10))
	}
	st, refs := store(b, chunks)
	open := func(h api.Hash) (blob.Object, error) {
		return st.Open(context.Background(), blob.ChunkKey("u", h))
	}
	r, _ := New(refs, 64*64<<10, open)
	defer r.Close()
	buf := make([]byte, 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		off := int64((i * 7919) % (64 * 64 << 10))
		if _, err := r.ReadAt(buf, off); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}
