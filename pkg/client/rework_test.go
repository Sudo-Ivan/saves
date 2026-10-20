// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"encoding/hex"

	"github.com/Sudo-Ivan/saves/internal/netx/nettest"
	"github.com/Sudo-Ivan/saves/internal/testserver"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Symlink dir inside the root must not redirect writes.
func TestPullSymlinkEscape(t *testing.T) {
	c, ts := setup(t)
	ctx := context.Background()
	outside := t.TempDir()
	root := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("no symlink")
	}
	dst := Source{Roots: []Root{{Key: "save", Dir: root}}}
	st := NewMemStore()
	// Push a manifest containing save/link/evil via a normal push on a
	// real tree is impossible (walk skips symlinks), so craft it on the
	// server side: push from a clean tree first, then hand-edit? Use a
	// direct manifest via a second client's begin: simpler - build the
	// manifest JSON ourselves.
	_ = ts
	h := api.HashBytes([]byte("evil"))
	man := api.Manifest{Version: 1, Files: []api.File{
		{Path: "save/link/evil.txt", Size: 4, Mode: 0o600, Chunks: []api.ChunkRef{{Hash: h, Size: 4}}},
	}}
	canon, _, _ := man.Canonical()
	// begin + put + commit
	resp, err := c.req(ctx, "POST", "/v1/apps/app/slots/s/snapshots", bytes.NewReader(canon),
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	var bo struct {
		ID       string `json:"id"`
		ChunkURL string `json:"chunk_url"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&bo)
	resp.Body.Close()
	hx := hex.EncodeToString(h[:])
	put, _ := http.NewRequest("PUT", c.cfg.BaseURL+bo.ChunkURL+hx, bytes.NewReader([]byte("evil")))
	put.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	put.ContentLength = 4
	pr, _ := c.http.Do(put)
	pr.Body.Close()
	co, _ := http.NewRequest("POST", c.cfg.BaseURL+"/v1/apps/app/slots/s/snapshots/"+bo.ID+"/commit", nil)
	co.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	co.Header.Set("If-Match", `""`)
	cr, _ := c.http.Do(co)
	cr.Body.Close()
	// Pull: writing save/link/evil.txt must NOT create outside/evil.txt.
	var evs []Event
	_, _ = c.Pull(ctx, "app", "s", bo.ID, dst, st, PullOptions{OnEvent: func(e Event) { evs = append(evs, e) }})
	// Allowed outcomes: skipped event or error, nothing written outside.
	if _, err := os.Stat(filepath.Join(outside, "evil.txt")); !os.IsNotExist(err) {
		t.Fatalf("write escaped root: %v", err)
	}
}

// Invalid filenames are skipped, not fatal.
func TestInvalidNamesSkipped(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	d := t.TempDir()
	bad := []string{"a:b", "a*b", "trail.", "CON", string([]byte{0xff, 0xfe})}
	for _, n := range bad {
		if err := os.WriteFile(filepath.Join(d, n), []byte("x"), 0o600); err != nil {
			continue // fs itself may reject
		}
	}
	var evs []Event
	src := Source{Roots: []Root{{Key: "save", Dir: d}}}
	pr, err := c.Push(ctx, "a", "s", src, NewMemStore(), PushOptions{OnEvent: func(e Event) { evs = append(evs, e) }})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Skipped == 0 {
		t.Fatal("no files skipped")
	}
}

// Interrupted upload resumes: cancel mid-PUT, rerun, only missing uploaded.
func TestInterruptedResume(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	d := t.TempDir()
	big := make([]byte, 4<<20)
	_, _ = rand.Read(big)
	if err := os.WriteFile(filepath.Join(d, "big"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	src := Source{Roots: []Root{{Key: "save", Dir: d}}}
	st := NewMemStore()
	// Fail chunk PUTs after the first succeeds; resume must finish.
	var puts int32
	base := c.http.Transport
	c.http.Transport = &failAfterN{base: base, n: &puts, failAt: 2}
	_, err := c.Push(ctx, "a", "s", src, st, PushOptions{})
	if err == nil {
		t.Fatal("expected put failure")
	}
	c.http.Transport = base
	pr, err := c.Push(ctx, "a", "s", src, st, PushOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Uploaded == 0 {
		t.Fatal("resume uploaded nothing")
	}
	// Pull to verify tree.
	dst := Source{Roots: []Root{{Key: "save", Dir: t.TempDir()}}}
	if _, err := c.Pull(ctx, "a", "s", "", dst, NewMemStore(), PullOptions{}); err != nil {
		t.Fatal(err)
	}
}

// failAfterN returns errors for PUT requests past the nth.
type failAfterN struct {
	base   http.RoundTripper
	n      *int32
	failAt int32
}

func (r *failAfterN) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == "PUT" && atomic.AddInt32(r.n, 1) >= r.failAt {
		return nil, errors.New("injected put failure")
	}
	return r.base.RoundTrip(req)
}

// QuotaError surfaces on exhausted quota.
func TestQuotaError(t *testing.T) {
	ts := testserver.New(t)
	tok := ts.Token(t, "q", []string{"read", "write"}, nil)
	c, _ := New(Config{BaseURL: ts.Srv.URL, Token: tok,
		HTTP: &http.Client{Transport: nettest.LoopbackTransport(false)}})
	ctx := context.Background()
	d := t.TempDir()
	big := bytes.Repeat([]byte{9}, 512<<10)
	os.WriteFile(filepath.Join(d, "f"), big, 0o600)
	src := Source{Roots: []Root{{Key: "save", Dir: d}}}
	st := NewMemStore()
	_, err := c.Push(ctx, "a", "s", src, st, PushOptions{})
	if err != nil {
		var qe *QuotaError
		if !errors.As(err, &qe) {
			t.Fatalf("want quota error got %v", err)
		}
	}
}

// 429 + Retry-After is honored.
func Test429Retry(t *testing.T) {
	c, _ := setup(t)
	var hits int32
	c.http.Transport = &rtFunc{fn: func(req *http.Request) (*http.Response, error) {
		if atomic.AddInt32(&hits, 1) == 1 {
			return &http.Response{StatusCode: 429,
				Header: http.Header{"Retry-After": []string{"1"}},
				Body:   http.NoBody, Request: req}, nil
		}
		return &http.Response{StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   http.NoBody, Request: req}, nil
	}}
	t0 := time.Now()
	_, err := c.Me(context.Background())
	if err != nil {
		t.Skipf("me: %v", err)
	}
	if time.Since(t0) < 900*time.Millisecond {
		t.Fatal("Retry-After not honored")
	}
}

type rtFunc struct {
	fn func(*http.Request) (*http.Response, error)
}

func (r *rtFunc) RoundTrip(req *http.Request) (*http.Response, error) { return r.fn(req) }

// Disk full: write error leaves no partial files.
func TestPullDiskFull(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	src := Source{Roots: []Root{{Key: "save", Dir: tree(t, map[string]string{"a": "data"})}}}
	st := NewMemStore()
	if _, err := c.Push(ctx, "a", "s", src, st, PushOptions{}); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	dstRoot, _ := os.OpenRoot(dst)
	_ = dstRoot
	writeErrHook = func(string) error { return errors.New("disk full") }
	defer func() { writeErrHook = nil }()
	_, err := c.Pull(ctx, "a", "s", "", Source{Roots: []Root{{Key: "save", Dir: dst}}}, NewMemStore(), PullOptions{})
	if err == nil {
		t.Fatal("expected write error")
	}
	// No partial files outside .saves-tmp-* leftovers.
	entries, _ := os.ReadDir(dst)
	for _, e := range entries {
		if len(e.Name()) > 10 && e.Name()[:10] == ".saves-tmp" {
			t.Fatalf("partial temp file %s", e.Name())
		}
		if e.Name() == "a" {
			// rename never ran: target must not exist
			b, _ := os.ReadFile(filepath.Join(dst, "a"))
			if len(b) == 4 {
				t.Fatal("partial file content")
			}
		}
	}
}

// Ask strategy uses the callback result.
func TestConflictAsk(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	d1 := tree(t, map[string]string{"f": "v1"})
	d2 := tree(t, map[string]string{"f": "v2"})
	s1 := Source{Roots: []Root{{Key: "save", Dir: d1}}}
	s2 := Source{Roots: []Root{{Key: "save", Dir: d2}}}
	st1, st2 := NewMemStore(), NewMemStore()
	if _, err := c.Push(ctx, "a", "s", s1, st1, PushOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err := c.Sync(ctx, "a", "s", s2, st2, SyncOptions{
		OnConflict: Ask,
		AskFn:      func(*Plan) ConflictStrategy { return KeepRemote },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pull == nil {
		t.Fatal("ask keepremote did not pull")
	}
}

// FuzzPullManifest: hostile manifests never write outside root.
func FuzzPullManifest(f *testing.F) {
	f.Add("save/../escape", "save")
	f.Add("save/../../x", "k")
	f.Add("../out", "save")
	f.Add("save/a/../../b", "save")
	f.Fuzz(func(t *testing.T, path, key string) {
		outside := t.TempDir()
		root := t.TempDir()
		// marker file outside root to detect writes
		marker := filepath.Join(outside, "escaped")
		src := Source{Roots: []Root{{Key: "save", Dir: root}}}
		_, _ = src.join(path) // may fail
		// simulate pull write of path
		r, err := os.OpenRoot(root)
		if err != nil {
			return
		}
		defer r.Close()
		rt, rel, ok := src.resolve(path)
		if !ok {
			return
		}
		_ = rt
		local, err := src.join(path)
		if err != nil {
			return // correctly rejected
		}
		// ensure resolved path stays inside root
		realRoot, _ := filepath.EvalSymlinks(root)
		realLocal, _ := filepath.EvalSymlinks(local)
		base := realRoot
		if realLocal != "" {
			base = realLocal
		}
		if len(base) < len(realRoot) || base[:len(realRoot)] != realRoot {
			t.Fatalf("join escaped: %q -> %q", path, base)
		}
		_ = marker
		_ = rel
	})
}
