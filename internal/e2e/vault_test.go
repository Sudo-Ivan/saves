// SPDX-License-Identifier: 0BSD

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultE2E(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	// device A
	envA := deviceEnv(t, "va")
	dir := t.TempDir()
	secret := "TOPSECRETMARKER" + strings.Repeat("z", 80<<10)
	dirB := t.TempDir()
	writeFileT(t, dir, "secret.dat", []byte(secret))
	writeFileT(t, dir, "other.dat", []byte("other"))
	pf := filepath.Join(t.TempDir(), "pass")
	os.WriteFile(pf, []byte("hunter2"), 0o600)
	// vault init
	c, out, e := run(t, envA, "setup", "--server", url, "--register")
	if c != 0 {
		t.Fatalf("setup A: %s %s", out, e)
	}
	c, out, e = run(t, envA, "vault", "init", "--passphrase-file", pf)
	if c != 0 {
		t.Fatalf("vault init: %d %s %s", c, out, e)
	}
	if !strings.Contains(out, "kid") {
		t.Fatalf("init out: %s", out)
	}
	// track + push encrypted
	if c, out, e := run(t, envA, "track", "add", "--path", dir, "--app", "vgame", "--key", "w"); c != 0 {
		t.Fatalf("track: %s %s", out, e)
	}
	c, out, e = run(t, envA, "push", "vgame")
	if c != 0 {
		t.Fatalf("push: %d %s %s", c, out, e)
	}
	// scan server data dir for plaintext
	found := false
	filepath.Walk(srvDataDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte("TOPSECRETMARKER")) || bytes.Contains(b, []byte("secret.dat")) {
			found = true
		}
		return nil
	})
	if found {
		t.Fatal("plaintext leaked into server data dir")
	}
	// device B: same account via A's token, unlock + pull.
	cfgPath := filepath.Join(os.Getenv("HOME"), "x")
	_ = cfgPath
	homeA := strings.TrimPrefix(envA[len(envA)-1], "")
	var jc struct{ Token string }
	for _, ev := range envA {
		if strings.HasPrefix(ev, "HOME=") {
			homeA = strings.TrimPrefix(ev, "HOME=")
		}
	}
	cb, err := os.ReadFile(filepath.Join(homeA, ".config/saves/config.json"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(cb, &jc)
	envB := deviceEnv(t, "vb")
	c, out, e = run(t, envB, "setup", "--server", url, "--token", jc.Token)
	if c != 0 {
		t.Fatalf("setup B: %s %s", out, e)
	}
	c, out, e = run(t, envB, "vault", "unlock", "--passphrase-file", pf)
	if c != 0 {
		t.Fatalf("unlock B: %d %s %s", c, out, e)
	}
	c, out, e = run(t, envB, "track", "add", "--path", dirB, "--app", "vgame", "--key", "w")
	if c != 0 {
		t.Fatalf("track B: %s %s", out, e)
	}
	c, out, e = run(t, envB, "pull", "vgame")
	if c != 0 {
		t.Fatalf("pull B: %d %s %s", c, out, e)
	}
	if got := readFileT(t, dirB, "secret.dat"); got != secret {
		t.Fatalf("B pulled %q", got[:40])
	}
	// wrong passphrase on device C
	pfBad := filepath.Join(t.TempDir(), "bad")
	os.WriteFile(pfBad, []byte("wrong"), 0o600)
	envC := deviceEnv(t, "vc")
	run(t, envC, "setup", "--server", url, "--token", jc.Token)
	c, _, _ = run(t, envC, "vault", "unlock", "--passphrase-file", pfBad)
	if c == 0 {
		t.Fatal("bad passphrase accepted")
	}
	t.Logf("bad pass exit=%d", c)
	_ = rand.Reader
}

func readFileT(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFileT(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
