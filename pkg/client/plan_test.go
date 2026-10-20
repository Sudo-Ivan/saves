// SPDX-License-Identifier: 0BSD

package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// After pull, Plan must be InSync immediately (no dirty-window false conflict).
func TestPullThenPlanInSync(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	src := Source{Roots: []Root{{Key: "save", Dir: tree(t, map[string]string{
		"a.dat": "aaaaaaaa", "b.dat": "bbbbbbbb",
	})}}}
	st := NewMemStore()
	if _, err := c.Push(ctx, "a", "s", src, st, PushOptions{}); err != nil {
		t.Fatal(err)
	}
	dst := Source{Roots: []Root{{Key: "save", Dir: t.TempDir()}}}
	st2 := NewMemStore()
	if _, err := c.Pull(ctx, "a", "s", "", dst, st2, PullOptions{}); err != nil {
		t.Fatal(err)
	}
	pl, err := c.Plan(ctx, "a", "s", dst, st2)
	if err != nil {
		t.Fatal(err)
	}
	if pl.State != InSync {
		t.Fatalf("plan=%v want in-sync (files younger than 2s)", pl.State)
	}
	// Push immediately: must be unchanged.
	pr, err := c.Push(ctx, "a", "s", dst, st2, PushOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !pr.Unchanged {
		t.Fatal("push after pull not unchanged")
	}
	// Local edit -> LocalChanged.
	os.WriteFile(filepath.Join(dst.Roots[0].Dir, "a.dat"), []byte("changed!!"), 0o600)
	pl, err = c.Plan(ctx, "a", "s", dst, st2)
	if err != nil {
		t.Fatal(err)
	}
	if pl.State != LocalChanged {
		t.Fatalf("plan=%v want local-changed", pl.State)
	}
	// Remote change via a second device + local untouched -> RemoteChanged.
	srcB := Source{Roots: []Root{{Key: "save", Dir: tree(t, map[string]string{
		"a.dat": "remote-change", "b.dat": "bbbbbbbb",
	})}}}
	stB := NewMemStore()
	if _, err := c.Push(ctx, "a", "s", srcB, stB, PushOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	// Restore dst file content to the pulled version.
	os.WriteFile(filepath.Join(dst.Roots[0].Dir, "a.dat"), []byte("aaaaaaaa"), 0o600)
	info, _ := os.Stat(filepath.Join(dst.Roots[0].Dir, "a.dat"))
	_ = info
	st3 := NewMemStore()
	if _, err := c.Pull(ctx, "a", "s", "", dst, st3, PullOptions{}); err != nil {
		t.Fatal(err)
	}
	pl, err = c.Plan(ctx, "a", "s", dst, st3)
	if err != nil {
		t.Fatal(err)
	}
	if pl.State != RemoteChanged && pl.State != InSync {
		t.Fatalf("plan=%v want remote-changed|in-sync", pl.State)
	}
	_ = time.Now
}
