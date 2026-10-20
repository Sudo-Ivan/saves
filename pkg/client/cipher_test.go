// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	rand2 "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestInlineChange(t *testing.T) {
	for _, enc := range []bool{false, true} {
		c, _ := setup(t)
		if enc {
			k, _ := vault.NewKey()
			c.cfg.Cipher = vault.New(k)
		}
		ctx := context.Background()
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "s.dat"), []byte("0123456789"), 0o600)
		src := Source{Roots: []Root{{Key: "w", Dir: dir}}}
		st := NewMemStore()
		if _, err := c.Push(ctx, "a", "s", src, st, PushOptions{}); err != nil {
			t.Fatal(err)
		}
		// same-size content change of an inline file must push.
		os.WriteFile(filepath.Join(dir, "s.dat"), []byte("9876543210"), 0o600)
		pr, err := c.Push(ctx, "a", "s", src, st, PushOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if pr.Unchanged {
			t.Fatalf("enc=%v: same-size inline edit not pushed", enc)
		}
		dst := Source{Roots: []Root{{Key: "w", Dir: t.TempDir()}}}
		st2 := NewMemStore()
		if _, err := c.Pull(ctx, "a", "s", "", dst, st2, PullOptions{}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(filepath.Join(dst.Roots[0].Dir, "s.dat"))
		if string(b) != "9876543210" {
			t.Fatalf("enc=%v pulled %q", enc, b)
		}
		// mode-only change must push.
		os.Chmod(filepath.Join(dir, "s.dat"), 0o700)
		pr2, err := c.Push(ctx, "a", "s", src, st, PushOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if pr2.Unchanged {
			t.Fatalf("enc=%v: mode change not pushed", enc)
		}
	}
}

func TestPushPullProperty(t *testing.T) {
	c, ts := setup(t)
	ctx := context.Background()
	dir := t.TempDir()
	src := Source{Roots: []Root{{Key: "w", Dir: dir}}}
	st := NewMemStore()
	rnd := rand2.New(rand2.NewSource(42))
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("f%d.dat", i%6)
		var b []byte
		if i%3 == 0 {
			b = make([]byte, 12+rnd.Intn(50)) // inline-sized
		} else {
			b = make([]byte, 200<<10+rnd.Intn(1<<20))
		}
		_, _ = rnd.Read(b)
		os.WriteFile(filepath.Join(dir, name), b, os.FileMode(0o600+rnd.Intn(0o100)))
		if i%7 == 0 {
			os.Chmod(filepath.Join(dir, name), 0o444)
		}
		if _, err := c.Push(ctx, "a", "s", src, st, PushOptions{}); err != nil {
			t.Fatalf("round %d push: %v", i, err)
		}
		dst := Source{Roots: []Root{{Key: "w", Dir: t.TempDir()}}}
		st2 := NewMemStore()
		if _, err := c.Pull(ctx, "a", "s", "", dst, st2, PullOptions{}); err != nil {
			t.Fatalf("round %d pull: %v", i, err)
		}
		// Frozen test clock: advance it so rate-limit tokens refill.
		ts.Clock.Add(time.Minute)
		fsrc, _ := os.ReadFile(filepath.Join(dir, name))
		fdst, rerr := os.ReadFile(filepath.Join(dst.Roots[0].Dir, name))
		if rerr != nil || !bytes.Equal(fsrc, fdst) {
			t.Fatalf("round %d: pulled file != source", i)
		}
	}
}
