// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/netx/nettest"
	"github.com/Sudo-Ivan/saves/internal/testserver"
)

func setup(t *testing.T) (*Client, *testserver.T) {
	t.Helper()
	ts := testserver.New(t)
	tok := ts.Token(t, "u1", []string{"read", "write"}, nil)
	c, err := New(Config{
		BaseURL: ts.Srv.URL, Token: tok,
		HTTP: &http.Client{Transport: nettest.LoopbackTransport(false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, ts
}

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for p, c := range files {
		full := filepath.Join(d, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Hour)
		_ = os.Chtimes(full, old, old)
	}
	return d
}

func TestRoundTrip(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	src := Source{Roots: []Root{{Key: "save", Dir: tree(t, map[string]string{
		"level.dat": "leveldata", "players/a.dat": "playerA",
		"big.dat": string(bytes.Repeat([]byte("x"), 200<<10)),
	})}}}
	st := NewMemStore()
	pr, err := c.Push(ctx, "app", "slot", src, st, PushOptions{Label: "one"})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Files != 3 || pr.Uploaded < 1 {
		t.Fatalf("push %+v", pr)
	}
	// Unchanged second push is a no-op.
	pr2, err := c.Push(ctx, "app", "slot", src, st, PushOptions{})
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			t.Logf("detail: %s", ae.Detail)
		}
		t.Fatal(err)
	}
	if !pr2.Unchanged {
		t.Fatalf("second push not unchanged: %+v", pr2)
	}
	// Pull into a different dir for the same key.
	dst := Source{Roots: []Root{{Key: "save", Dir: t.TempDir()}}}
	st2 := NewMemStore()
	pres, err := c.Pull(ctx, "app", "slot", "", dst, st2, PullOptions{})
	if err != nil {
		t.Fatalf("pull err: %v", err)
	}
	if pres.Written != 3 {
		t.Fatalf("pull %+v", pres)
	}
	b, err := os.ReadFile(filepath.Join(dst.Roots[0].Dir, "level.dat"))
	if err != nil || string(b) != "leveldata" {
		t.Fatalf("content %q err %v", b, err)
	}
}

func TestDelta(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	d := t.TempDir()
	big := bytes.Repeat([]byte("A"), 20<<20)
	path := filepath.Join(d, "big.bin")
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	src := Source{Roots: []Root{{Key: "save", Dir: d}}}
	st := NewMemStore()
	if _, err := c.Push(ctx, "app", "slot", src, st, PushOptions{}); err != nil {
		t.Fatal(err)
	}
	// Flip one byte.
	big[5<<20] = 'B'
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	pr, err := c.Push(ctx, "app", "slot", src, st, PushOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Uploaded > 2 {
		t.Fatalf("delta uploaded %d chunks", pr.Uploaded)
	}
}

func TestConflict(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	d1 := tree(t, map[string]string{"f": "v1"})
	d2 := tree(t, map[string]string{"f": "v2"})
	src1 := Source{Roots: []Root{{Key: "save", Dir: d1}}}
	src2 := Source{Roots: []Root{{Key: "save", Dir: d2}}}
	st1, st2 := NewMemStore(), NewMemStore()
	if _, err := c.Push(ctx, "a", "s", src1, st1, PushOptions{}); err != nil {
		t.Fatal(err)
	}
	// Second device has no prior state so its If-Match "" conflicts.
	var ce *ConflictError
	_, err := c.Push(ctx, "a", "s", src2, st2, PushOptions{})
	if !errors.As(err, &ce) {
		t.Fatalf("want conflict got %v", err)
	}
	if ce.Head == "" {
		t.Fatal("empty head")
	}
	// Sync with KeepRemote pulls head into device 2.
	if _, err := c.Sync(ctx, "a", "s", src2, st2, SyncOptions{OnConflict: KeepRemote}); err != nil {
		t.Fatal(err)
	}
	// Force resolves a stale-head push.
	if _, err := c.Push(ctx, "a", "s", src2, st2, PushOptions{Force: true}); err != nil {
		t.Fatalf("force %v", err)
	}
}

func TestSyncStates(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	d := tree(t, map[string]string{"f": "data"})
	src := Source{Roots: []Root{{Key: "save", Dir: d}}}
	st := NewMemStore()
	p, err := c.Plan(ctx, "a", "s", src, st)
	if err != nil || p.State != NoRemote {
		t.Fatalf("plan %v %v", p.State, err)
	}
	if _, err := c.Sync(ctx, "a", "s", src, st, SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	p, err = c.Plan(ctx, "a", "s", src, st)
	if err != nil || p.State != InSync {
		t.Fatalf("plan2 %v %v", p.State, err)
	}
}

func FuzzIgnore(f *testing.F) {
	f.Add("*.tmp", "a.tmp", false)
	f.Add("/a/b", "a/b/c", true)
	f.Add("!keep.tmp", "x/keep.tmp", false)
	f.Fuzz(func(t *testing.T, pat, path string, dir bool) {
		ig, err := ParseIgnore(bytes.NewReader([]byte(pat)))
		if err != nil {
			return
		}
		_ = ig.Match(path, dir) // must not panic or hang
	})
}

func FuzzSourceMapping(f *testing.F) {
	f.Add("save", "../x")
	f.Add("key", "a/../../../etc")
	f.Fuzz(func(t *testing.T, key, rel string) {
		src := Source{Roots: []Root{{Key: key, Dir: "/root"}}}
		got, err := src.join(key + "/" + rel)
		if err != nil {
			return
		}
		r, err2 := filepath.Rel("/root", got)
		if err2 != nil || r == ".." || len(r) > 2 && r[:3] == ".." {
			t.Fatalf("escape %q -> %q", rel, got)
		}
	})
}

// Retried requests replay the same body bytes.
func TestRetryBodyReplay(t *testing.T) {
	var bodies [][]byte
	c, _ := setup(t)
	c.http.Transport = &rtFunc{fn: func(req *http.Request) (*http.Response, error) {
		var b []byte
		if req.Body != nil {
			b, _ = io.ReadAll(req.Body)
		}
		bodies = append(bodies, b)
		if len(bodies) == 1 {
			return &http.Response{StatusCode: 429,
				Header: http.Header{"Retry-After": []string{"0"}},
				Body:   http.NoBody, Request: req}, nil
		}
		return &http.Response{StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(bytes.NewReader([]byte("{}"))), Request: req}, nil
	}}
	_, err := c.Me(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("bodies %v", bodies)
	}
}

// quota_exceeded must never be retried.
func TestNoRetryQuota(t *testing.T) {
	var n int32
	c, _ := setup(t)
	c.http.Transport = &rtFunc{fn: func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&n, 1)
		return &http.Response{StatusCode: 429,
			Header: http.Header{
				"Content-Type": []string{"application/problem+json"}},
			Body: io.NopCloser(bytes.NewReader(
				[]byte(`{"code":"quota_exceeded","status":429}`))),
			Request: req}, nil
	}}
	_, err := c.Me(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if atomic.LoadInt32(&n) != 1 {
		t.Fatalf("retried %d times", n)
	}
}
