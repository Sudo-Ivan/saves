// SPDX-License-Identifier: 0BSD

// Package blobtest is the conformance suite every blob.Store
// implementation must pass.
package blobtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Run executes the conformance suite against a store factory. The
// factory must return a fresh empty store per call.
func Run(t *testing.T, factory func(t *testing.T) blob.Store) {
	t.Run("ValidKey", func(t *testing.T) { testValidKey(t, factory(t)) })
	t.Run("PutOpen", func(t *testing.T) { testPutOpen(t, factory(t)) })
	t.Run("ChecksumMismatch", func(t *testing.T) { testChecksumMismatch(t, factory(t)) })
	t.Run("SizeMismatch", func(t *testing.T) { testSizeMismatch(t, factory(t)) })
	t.Run("Reput", func(t *testing.T) { testReput(t, factory(t)) })
	t.Run("ConcurrentPuts", func(t *testing.T) { testConcurrentPuts(t, factory(t)) })
	t.Run("Delete", func(t *testing.T) { testDelete(t, factory(t)) })
	t.Run("List", func(t *testing.T) { testList(t, factory(t)) })
	t.Run("InvalidKeysRejected", func(t *testing.T) { testInvalidKeys(t, factory(t)) })
	t.Run("LargeRanged", func(t *testing.T) { testLargeRanged(t, factory(t)) })
	t.Run("CancelMidPut", func(t *testing.T) { testCancelMidPut(t, factory(t)) })
}

func hashOf(b []byte) api.Hash { return api.HashBytes(b) }

func put(t *testing.T, s blob.Store, uid string, data []byte) string {
	t.Helper()
	h := hashOf(data)
	key := blob.ChunkKey(uid, h)
	if err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)), &h); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return key
}

func testValidKey(t *testing.T, s blob.Store) {
	t.Helper()
	good := blob.ChunkKey("user-1_X", api.HashBytes([]byte("x")))
	if err := blob.ValidKey(good); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	bad := []string{
		"", "u", "u/", "u/a", "u/a/c", "u/a/c/", "u//c/" + strings.Repeat("a", 64),
		"u/a/x/" + strings.Repeat("a", 64), "u/a/c/" + strings.Repeat("a", 63),
		"u/a/c/" + strings.Repeat("A", 64), "u/a/c/" + strings.Repeat("g", 64),
		"u/a/c/" + strings.Repeat("a", 64) + "/extra", "../u/a/c/" + strings.Repeat("a", 64),
		"u/a/../c/" + strings.Repeat("a", 64), "u/a.b/c/" + strings.Repeat("a", 64),
		"tmp/foo", "u/" + strings.Repeat("u", 65) + "/c/" + strings.Repeat("a", 64),
	}
	for _, k := range bad {
		if err := blob.ValidKey(k); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
}

func testPutOpen(t *testing.T, s blob.Store) {
	t.Helper()
	ctx := context.Background()
	data := []byte("hello blob")
	key := put(t, s, "u1", data)

	obj, err := s.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Close()
	if obj.Size() != int64(len(data)) {
		t.Fatalf("size %d", obj.Size())
	}
	p := make([]byte, len(data))
	if n, err := obj.ReadAt(p, 0); err != nil || n != len(data) {
		t.Fatalf("ReadAt(0): n=%d err=%v", n, err)
	}
	if !bytes.Equal(p, data) {
		t.Fatal("content mismatch")
	}
	if n, err := obj.ReadAt(p, int64(len(data))); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt(end): n=%d err=%v", n, err)
	}
	if n, err := obj.ReadAt(p, int64(len(data))+10); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt(past end): n=%d err=%v", n, err)
	}
	q := make([]byte, 5)
	if n, err := obj.ReadAt(q, 3); err != nil || n != 5 {
		t.Fatalf("ReadAt(3): n=%d err=%v", n, err)
	}
	if string(q) != "lo bl" {
		t.Fatalf("got %q", q)
	}

	// Zero length object.
	zh := hashOf(nil)
	zkey := blob.ChunkKey("u1", zh)
	if err := s.Put(ctx, zkey, bytes.NewReader(nil), 0, &zh); err != nil {
		t.Fatalf("zero Put: %v", err)
	}
	zobj, err := s.Open(ctx, zkey)
	if err != nil {
		t.Fatal(err)
	}
	defer zobj.Close()
	if n, err := zobj.ReadAt(make([]byte, 1), 0); n != 0 || err != io.EOF {
		t.Fatalf("zero ReadAt: n=%d err=%v", n, err)
	}
	if sz, err := s.Stat(ctx, zkey); err != nil || sz != 0 {
		t.Fatalf("zero Stat: %d %v", sz, err)
	}
}

func testChecksumMismatch(t *testing.T, s blob.Store) {
	t.Helper()
	ctx := context.Background()
	data := []byte("checksum content")
	bad := hashOf([]byte("other"))
	key := blob.ChunkKey("u2", bad)
	if err := s.Put(ctx, key, bytes.NewReader(data), int64(len(data)), &bad); !errors.Is(err, blob.ErrChecksum) {
		t.Fatalf("want ErrChecksum, got %v", err)
	}
	if _, err := s.Open(ctx, key); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("object visible after checksum failure: %v", err)
	}
}

func testSizeMismatch(t *testing.T, s blob.Store) {
	t.Helper()
	ctx := context.Background()
	data := []byte("size content")
	h := hashOf(data)
	key := blob.ChunkKey("u3", h)
	if err := s.Put(ctx, key, bytes.NewReader(data), int64(len(data)+1), &h); !errors.Is(err, blob.ErrSizeMismatch) {
		t.Fatalf("short stream: want ErrSizeMismatch, got %v", err)
	}
	if err := s.Put(ctx, key, bytes.NewReader(data), int64(len(data)-1), &h); !errors.Is(err, blob.ErrSizeMismatch) {
		t.Fatalf("long stream: want ErrSizeMismatch, got %v", err)
	}
	if _, err := s.Open(ctx, key); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("object visible after size failure: %v", err)
	}
}

func testReput(t *testing.T, s blob.Store) {
	t.Helper()
	data := []byte("reput content")
	key := put(t, s, "u4", data)
	h := hashOf(data)
	if err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)), &h); err != nil {
		t.Fatalf("idempotent reput: %v", err)
	}
}

func testConcurrentPuts(t *testing.T, s blob.Store) {
	t.Helper()
	ctx := context.Background()
	var wg sync.WaitGroup
	// Identical content racing.
	data := []byte("same content racing")
	h := hashOf(data)
	key := blob.ChunkKey("u5", h)
	errs := make(chan error, 16)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Put(ctx, key, bytes.NewReader(data), int64(len(data)), &h)
		}()
	}
	// Distinct content racing.
	for i := 0; i < 8; i++ {
		d := []byte{byte(i), 'd', 'i', 's', 't'}
		dh := hashOf(d)
		dkey := blob.ChunkKey("u5", dh)
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Put(ctx, dkey, bytes.NewReader(d), int64(len(d)), &dh)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent put: %v", err)
		}
	}
}

func testDelete(t *testing.T, s blob.Store) {
	t.Helper()
	ctx := context.Background()
	key := put(t, s, "u6", []byte("delete me"))
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal("second delete not idempotent")
	}
	if _, err := s.Open(ctx, key); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("deleted object still open: %v", err)
	}
}

func testList(t *testing.T, s blob.Store) {
	t.Helper()
	ctx := context.Background()
	put(t, s, "ul", []byte("a1"))
	put(t, s, "ul", []byte("a2"))
	put(t, s, "ul", []byte("a3"))
	put(t, s, "other", []byte("b1"))
	mh := hashOf([]byte("manifest bytes"))
	mkey := blob.ManifestKey("ul", mh)
	if err := s.Put(ctx, mkey, bytes.NewReader([]byte("manifest bytes")), int64(len("manifest bytes")), &mh); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := s.List(ctx, "u/ul/c/", func(e blob.Entry) error {
		got = append(got, e.Key)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("list got %d entries: %v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("list not sorted: %v", got)
		}
	}
	// Prefix u/ul catches both kinds.
	var all []string
	if err := s.List(ctx, "u/ul/", func(e blob.Entry) error {
		all = append(all, e.Key)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("list all got %d", len(all))
	}
	// Early stop.
	var one []string
	stop := errors.New("stop")
	if err := s.List(ctx, "u/ul/", func(e blob.Entry) error {
		one = append(one, e.Key)
		return stop
	}); !errors.Is(err, stop) || len(one) != 1 {
		t.Fatalf("early stop: %v %v", err, one)
	}
}

func testInvalidKeys(t *testing.T, s blob.Store) {
	t.Helper()
	ctx := context.Background()
	bad := "u/a/c/" + strings.Repeat("z", 64)
	h := hashOf(nil)
	if err := s.Put(ctx, bad, bytes.NewReader(nil), 0, &h); !errors.Is(err, blob.ErrInvalidKey) {
		t.Fatalf("Put invalid: %v", err)
	}
	if _, err := s.Open(ctx, bad); !errors.Is(err, blob.ErrInvalidKey) {
		t.Fatalf("Open invalid: %v", err)
	}
	if _, err := s.Stat(ctx, bad); !errors.Is(err, blob.ErrInvalidKey) {
		t.Fatalf("Stat invalid: %v", err)
	}
	if err := s.Delete(ctx, bad); !errors.Is(err, blob.ErrInvalidKey) {
		t.Fatalf("Delete invalid: %v", err)
	}
}

func testLargeRanged(t *testing.T, s blob.Store) {
	t.Helper()
	ctx := context.Background()
	data := make([]byte, 32<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	key := put(t, s, "ubig", data)
	obj, err := s.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Close()
	for _, off := range []int64{0, 1 << 10, 3 << 20, (32 << 20) - 4096} {
		p := make([]byte, 4096)
		n, err := obj.ReadAt(p, off)
		if err != nil || n != 4096 {
			t.Fatalf("ReadAt(%d): n=%d err=%v", off, n, err)
		}
		if !bytes.Equal(p, data[off:off+4096]) {
			t.Fatalf("ReadAt(%d) content mismatch", off)
		}
	}
}

type cancelReader struct {
	ctx   context.Context
	r     io.Reader
	after int
	n     int
}

func (c *cancelReader) Read(p []byte) (int, error) {
	c.n += len(p)
	if c.n > c.after {
		return 0, c.ctx.Err()
	}
	return c.r.Read(p)
}

func testCancelMidPut(t *testing.T, s blob.Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	data := make([]byte, 2<<20)
	rand.Read(data)
	h := hashOf(data)
	key := blob.ChunkKey("u9", h)
	cancel()
	err := s.Put(ctx, key, &cancelReader{ctx: ctx, r: bytes.NewReader(data), after: 1024}, int64(len(data)), &h)
	if err == nil {
		t.Fatal("cancelled put succeeded")
	}
	if _, err := s.Open(context.Background(), key); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("partial object visible: %v", err)
	}
	var found bool
	if err := s.List(context.Background(), "u/u9/", func(e blob.Entry) error {
		found = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("partial object listed")
	}
}
