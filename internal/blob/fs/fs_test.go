// SPDX-License-Identifier: 0BSD

package fs

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/blob/blobtest"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func factory(t *testing.T) blob.Store {
	t.Helper()
	s, err := New(Options{Root: t.TempDir(), Fsync: "never"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestConformance(t *testing.T) {
	blobtest.Run(t, factory)
}

func TestSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Root: root, Fsync: "never"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// A symlink inside the root pointing outside must not be followed.
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.root.Stat("escape"); err == nil {
		t.Fatal("symlink escape resolved")
	}
	// Even a symlinked directory mid-path must not escape.
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "u")); err != nil {
		t.Fatal(err)
	}
	key := blob.ChunkKey("x", api.HashBytes([]byte("z")))
	if err := s.Put(context.Background(), key, bytes.NewReader([]byte("z")), 1, ptr(api.HashBytes([]byte("z")))); err == nil {
		t.Fatal("put through symlinked dir succeeded")
	}
	found := 0
	filepath.WalkDir(filepath.Dir(outside), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found++
		}
		return nil
	})
	if found != 1 {
		t.Fatalf("wrote outside root: %d files found", found)
	}
}

func ptr(h api.Hash) *api.Hash { return &h }

func TestStaleTempCleanup(t *testing.T) {
	root := t.TempDir()
	s, err := New(Options{Root: root, Fsync: "never"})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	stale := filepath.Join(root, "tmp", "stale1")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(root, "tmp", "fresh1")
	if err := os.WriteFile(fresh, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := New(Options{Root: root, Fsync: "never"})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temp not cleaned")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh temp removed")
	}
	var listed []string
	if err := s2.List(context.Background(), "", func(e blob.Entry) error {
		listed = append(listed, e.Key)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Fatalf("tmp contents leaked into list: %v", listed)
	}
}

func TestFsyncModes(t *testing.T) {
	for _, mode := range []string{"always", "dir", "never"} {
		t.Run(mode, func(t *testing.T) {
			s, err := New(Options{Root: t.TempDir(), Fsync: mode})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			data := []byte("fsync content")
			h := api.HashBytes(data)
			if err := s.Put(context.Background(), blob.ChunkKey("u", h), bytes.NewReader(data), int64(len(data)), &h); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPermissions(t *testing.T) {
	root := t.TempDir()
	s, err := New(Options{Root: root, Fsync: "never"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	data := []byte("perm check")
	h := api.HashBytes(data)
	key := blob.ChunkKey("u", h)
	if err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)), &h); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(root, storePath(key)))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %04o", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Join(root, "u", "u", "c", h.String()[:2]))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %04o", di.Mode().Perm())
	}
	ri, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if ri.Mode().Perm() != 0o700 {
		t.Fatalf("root mode %04o", ri.Mode().Perm())
	}
}

func TestFileObjectExposed(t *testing.T) {
	s := factory(t)
	data := []byte("sendfile")
	h := api.HashBytes(data)
	key := blob.ChunkKey("u", h)
	if err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)), &h); err != nil {
		t.Fatal(err)
	}
	obj, err := s.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Close()
	fo, ok := obj.(blob.FileObject)
	if !ok {
		t.Fatal("object does not expose File()")
	}
	if fo.File() == nil {
		t.Fatal("nil file")
	}
}

func BenchmarkPut1MiB(b *testing.B) {
	benchPut(b, 1<<20)
}

func BenchmarkPut4MiB(b *testing.B) {
	benchPut(b, 4<<20)
}

func benchPut(b *testing.B, size int) {
	s, err := New(Options{Root: b.TempDir(), Fsync: "never"})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	data := make([]byte, size)
	rand.Read(data)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data[0] = byte(i) // fresh content each iteration
		h := api.HashBytes(data)
		if err := s.Put(b.Context(), blob.ChunkKey("u", h), bytes.NewReader(data), int64(size), &h); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadAt4KiB(b *testing.B) {
	benchReadAt(b, 4096)
}

func BenchmarkReadAt1MiB(b *testing.B) {
	benchReadAt(b, 1<<20)
}

func benchReadAt(b *testing.B, n int64) {
	s, err := New(Options{Root: b.TempDir(), Fsync: "never"})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	data := make([]byte, 8<<20)
	rand.Read(data)
	h := api.HashBytes(data)
	key := blob.ChunkKey("u", h)
	if err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)), &h); err != nil {
		b.Fatal(err)
	}
	obj, err := s.Open(context.Background(), key)
	if err != nil {
		b.Fatal(err)
	}
	defer obj.Close()
	p := make([]byte, n)
	b.SetBytes(n)
	b.ResetTimer()
	maxOff := int64(len(data)) - n
	for i := 0; i < b.N; i++ {
		off := int64(i*7919) % maxOff
		if _, err := obj.ReadAt(p, off); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzFSPutOpen(f *testing.F) {
	f.Add("u1", []byte("fuzz content"))
	f.Fuzz(func(t *testing.T, uid string, data []byte) {
		if uid == "" {
			uid = "u"
		}
		var bu strings.Builder
		for _, c := range uid {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
				bu.WriteRune(c)
			}
		}
		if bu.Len() == 0 || bu.Len() > 64 {
			return
		}
		s, err := New(Options{Root: t.TempDir(), Fsync: "never"})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		h := api.HashBytes(data)
		key := blob.ChunkKey(bu.String(), h)
		if err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)), &h); err != nil {
			t.Fatal(err)
		}
		obj, err := s.Open(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		defer obj.Close()
		got := make([]byte, len(data))
		if _, err := obj.ReadAt(got, 0); err != nil && len(data) > 0 {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("content mismatch")
		}
	})
}
