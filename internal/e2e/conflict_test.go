// SPDX-License-Identifier: 0BSD

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func trackPair(t *testing.T, url string) ([]string, []string, string, string) {
	t.Helper()
	envA := deviceEnv(t, "A")
	envB := deviceEnv(t, "B")
	hA, hB := envHome(envA), envHome(envB)
	writeFile(t, hA, "g/save.dat", "A-data")
	writeFile(t, hB, "g/save.dat", "A-data")
	code, _, se := run(t, envA, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup A: %s", se)
	}
	b, _ := os.ReadFile(hA + "/.config/saves/config.json")
	var jc struct{ Token string }
	json.Unmarshal(b, &jc)
	code, _, se = run(t, envB, "setup", "--server", url, "--token", jc.Token)
	if code != 0 {
		t.Fatalf("setup B: %s", se)
	}
	for i, env := range [][]string{envA, envB} {
		home := hB
		if i == 0 {
			home = hA
		}
		code, _, se := run(t, env, "track", "add", "--path", home+"/g",
			"--app", "conflictgame", "--slot", "s")
		if code != 0 {
			t.Fatalf("track: %s", se)
		}
	}
	return envA, envB, hA, hB
}

func TestConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	url, stop := startServer(t)
	defer stop()
	envA, envB, hA, hB := trackPair(t, url)
	// Both modify, A pushes first.
	writeFile(t, hA, "g/save.dat", "A-v2")
	writeFile(t, hB, "g/save.dat", "B-v2")
	code, _, se := run(t, envA, "push", "--all")
	if code != 0 {
		t.Fatalf("push A: %s", se)
	}
	// B sync non-interactive: conflict exit 3.
	var out string
	code, _, se = run(t, envB, "sync", "--all")
	if code != 3 {
		t.Fatalf("want exit 3 got %d err=%s", code, se)
	}
	// keep-remote: B gets A's data, backup has B's file.
	code, out, se = run(t, envB, "sync", "--all", "--on-conflict", "keep-remote", "--json")
	t.Logf("keep-remote: %d %q %q", code, out, se)
	if code != 0 {
		t.Fatalf("sync keep-remote: %d %s", code, se)
	}
	if got := readFile(t, hB, "g/save.dat"); got != "A-v2" {
		t.Fatalf("B file %q", got)
	}
	_, out, _ = run(t, envB, "backups", "list", "--json")
	t.Logf("backups: %s", out)
	// restore backup
	code, _, se = run(t, envB, "backups", "restore", "conflictgame/s")
	t.Logf("restore: %d %s", code, se)
	// keep-local on a fresh pair
	envA2, envB2, hA2, hB2 := trackPair(t, url)
	_ = envA2
	writeFile(t, hA2, "g/save.dat", "A2-v2")
	writeFile(t, hB2, "g/save.dat", "B2-v2")
	code, _, se = run(t, envA2, "push", "--all")
	if code != 0 {
		t.Fatalf("push A2: %s", se)
	}
	code, _, se = run(t, envB2, "sync", "--all", "--on-conflict", "keep-local")
	t.Logf("keep-local sync: %d %s", code, se)
	if got := readFile(t, hB2, "g/save.dat"); got != "B2-v2" {
		t.Fatalf("B2 file %q", got)
	}
}

// Locked world: helper holds fcntl write lock on session.lock.
func TestLockedWorld(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	if os.Getenv("E2E_LOCKHELPER") == "1" {
		dir := os.Getenv("E2E_LOCKDIR")
		f, _ := os.OpenFile(filepath.Join(dir, "session.lock"), os.O_RDWR|os.O_CREATE, 0o600)
		var fl syscall.Flock_t
		fl.Type = syscall.F_WRLCK
		syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &fl)
		os.Stdout.WriteString("locked")
		select {}
	}
	url, stop := startServer(t)
	defer stop()
	envA := deviceEnv(t, "A")
	hA := envHome(envA)
	mkWorld(t, hA+"/.minecraft/saves/W", "W", 0)
	code, _, se := run(t, envA, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup: %s", se)
	}
	run(t, envA, "track", "auto")
	// lock the world
	cmd := exec.Command(os.Args[0], "-test.run=TestLockedWorld")
	cmd.Env = append(os.Environ(), "E2E_LOCKHELPER=1",
		"E2E_LOCKDIR="+hA+"/.minecraft/saves/W")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	buf := make([]byte, 16)
	out.Read(buf)
	time.Sleep(100 * time.Millisecond)
	code, _, se = run(t, envA, "push", "--all")
	if code != 1 {
		t.Fatalf("want exit 1 got %d err=%s", code, se)
	}
	if !strings.Contains(se, "locked") && !strings.Contains(se, "force-locked") {
		t.Fatalf("no lock message: %s", se)
	}
	code, _, se = run(t, envA, "push", "--all", "--force-locked")
	if code != 0 {
		t.Fatalf("force-locked push: %d %s", code, se)
	}
	_ = bytes.MinRead
}
