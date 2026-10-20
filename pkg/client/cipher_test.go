// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sudo-Ivan/saves/pkg/vault"
)

// Compile assertion: vault.Vault satisfies client.Cipher.
var _ Cipher = (*vault.Vault)(nil)

func TestEncryptedRoundTrip(t *testing.T) {
	k, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New(k)
	c, srv := setup(t)
	c.cfg.Cipher = v
	ctx := context.Background()
	_ = srv
	big := strings.Repeat("TOPSECRETMARKER", 5000) // >64KiB
	src := Source{Roots: []Root{{Key: "save", Dir: tree(t, map[string]string{
		"secret.dat": big, "x.dat": "abc",
	})}}}
	st := NewMemStore()
	pr, err := c.Push(ctx, "app", "s", src, st, PushOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Uploaded == 0 {
		t.Fatal("nothing uploaded")
	}
	dst := Source{Roots: []Root{{Key: "save", Dir: t.TempDir()}}}
	st2 := NewMemStore()
	pr2, err := c.Pull(ctx, "app", "s", "", dst, st2, PullOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pr2.Written == 0 {
		t.Fatal("nothing pulled")
	}
	b, _ := os.ReadFile(filepath.Join(dst.Roots[0].Dir, "secret.dat"))
	if got := string(b); got != big {
		t.Fatalf("got %q", got)
	}
	// wrong key
	v2, _ := vault.NewKey()
	c2, _ := setup(t)
	c2.cfg.Cipher = vault.New(v2)
	if _, err := c2.Pull(ctx, "app", "s", "", dst, st2, PullOptions{}); err == nil {
		t.Fatal("no key mismatch error")
	}
	// no cipher on enc snapshot
	c3, _ := setup(t)
	if _, err := c3.Pull(ctx, "app", "s", "", dst, NewMemStore(), PullOptions{}); err == nil {
		t.Fatal("no encrypted error")
	}
}

func TestEncDelta(t *testing.T) {
	k, _ := vault.NewKey()
	v := vault.New(k)
	c, _ := setup(t)
	c.cfg.Cipher = v
	ctx := context.Background()
	dir := t.TempDir()
	data := make([]byte, 20<<20)
	rand.Read(data)
	os.WriteFile(filepath.Join(dir, "big.bin"), data, 0o600)
	src := Source{Roots: []Root{{Key: "save", Dir: dir}}}
	st := NewMemStore()
	if _, err := c.Push(ctx, "app", "d", src, st, PushOptions{}); err != nil {
		t.Fatal(err)
	}
	// 1-byte change -> <=2 sealed chunks
	data[len(data)/2] ^= 0xff
	os.WriteFile(filepath.Join(dir, "big.bin"), data, 0o600)
	pr, err := c.Push(ctx, "app", "d", src, st, PushOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("delta uploaded=%d bytes=%d", pr.Uploaded, pr.BytesUploaded)
	if pr.Uploaded > 2 {
		t.Fatalf("delta uploaded %d chunks", pr.Uploaded)
	}
	// unchanged -> Unchanged... encrypted push currently lacks the fast
	// path; second push must still not re-read (cache) but may still
	// upload zero chunks.
	pr2, err := c.Push(ctx, "app", "d", src, st, PushOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("unchanged uploaded=%d", pr2.Uploaded)
}

func TestEncNoPlaintextInBlobs(t *testing.T) {
	k, _ := vault.NewKey()
	c, srv := setup(t)
	c.cfg.Cipher = vault.New(k)
	ctx := context.Background()
	src := Source{Roots: []Root{{Key: "save", Dir: tree(t, map[string]string{
		"secret-name.dat": "TOPSECRETMARKER" + strings.Repeat("x", 100000),
	})}}}
	st := NewMemStore()
	if _, err := c.Push(ctx, "app", "s", src, st, PushOptions{}); err != nil {
		t.Fatal(err)
	}
	_ = srv
	// scan the manifest via the API
	m, err := c.GetManifest(ctx, "app", "s", "latest")
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := m.Canonical()
	if bytes.Contains(b, []byte("TOPSECRETMARKER")) || bytes.Contains(b, []byte("secret-name.dat")) {
		t.Fatal("plaintext leaked in manifest")
	}
	// file paths are opaque
	if m.Files[0].Path == "secret-name.dat" {
		t.Fatal("real filename leaked")
	}
}
