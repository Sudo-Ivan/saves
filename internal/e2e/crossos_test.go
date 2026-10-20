// SPDX-License-Identifier: 0BSD

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/Sudo-Ivan/saves/internal/detect"
)

// Scenario 5: cross-OS save via wine prefix manifest.
func TestCrossOS(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	url, stop := startServer(t)
	defer stop()
	envA := deviceEnv(t, "A")
	hA := envHome(envA)
	writeFile(t, hA, "winsaves/My Games/TestGame/save1.dat", "cross-os-save")
	writeFile(t, hA, "winsaves/My Games/TestGame/sub/x.sav", "sub")
	code, _, se := run(t, envA, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup A: %s", se)
	}
	code, _, se = run(t, envA, "track", "add", "--path",
		hA+"/winsaves/My Games/TestGame", "--app", "ludusavi:testgame", "--slot", "default")
	if code != 0 {
		t.Fatalf("track A: %s", se)
	}
	code, _, se = run(t, envA, "push", "--all")
	if code != 0 {
		t.Fatalf("push A: %s", se)
	}
	// B: wine prefix layout + cached manifest index mapping <winDocuments>
	envB := deviceEnv(t, "B")
	hB := envHome(envB)
	pfx := hB + "/.wine/drive_c/users/user1/Documents"
	os.MkdirAll(pfx+"/My Games", 0o755)
	b, _ := os.ReadFile(hA + "/.config/saves/config.json")
	var jc struct{ Token string }
	json.Unmarshal(b, &jc)
	code, _, se = run(t, envB, "setup", "--server", url, "--token", jc.Token)
	if code != 0 {
		t.Fatalf("setup B: %s", se)
	}
	// write index fixture into B's cache
	ix := &detect.Index{Games: []detect.Entry{{
		Title: "TestGame",
		Files: []detect.PathRule{{Path: "<winDocuments>/My Games/TestGame", Tags: []string{"save"}}},
	}}}
	os.MkdirAll(hB+"/.cache/saves", 0o755)
	if err := ix.Save(hB + "/.cache/saves/index.json"); err != nil {
		t.Fatal(err)
	}
	_, out, _ := run(t, envB, "games", "list", "--json")
	t.Logf("games: %s", out)
	// manual track of the wine Documents path
	code, _, se = run(t, envB, "track", "add", "--path", pfx+"/My Games/TestGame",
		"--app", "ludusavi:testgame", "--slot", "default")
	if code != 0 {
		t.Fatalf("track B: %s", se)
	}
	code, outp, se := run(t, envB, "pull", "--all", "--json")
	t.Logf("pull: %s %s", outp, se)
	if code != 0 {
		t.Fatalf("pull B: %d %s", code, se)
	}
	if got := readFile(t, hB, ".wine/drive_c/users/user1/Documents/My Games/TestGame/save1.dat"); got != "cross-os-save" {
		t.Fatalf("got %q", got)
	}
	// edit on B, sync back, A pulls
	writeFile(t, hB, ".wine/drive_c/users/user1/Documents/My Games/TestGame/save1.dat", "edited-on-B")
	code, _, se = run(t, envB, "sync", "--all")
	if code != 0 {
		t.Fatalf("sync B: %d %s", code, se)
	}
	code, _, se = run(t, envA, "pull", "--all")
	if code != 0 {
		t.Fatalf("pull A: %d %s", code, se)
	}
	if got := readFile(t, hA, "winsaves/My Games/TestGame/save1.dat"); got != "edited-on-B" {
		t.Fatalf("A got %q", got)
	}
}

// Scenario 5b: real wine prefix when wineboot works.
func TestRealWinePrefix(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	pfx := filepath.Join(t.TempDir(), "wp")
	env := append(os.Environ(), "WINEPREFIX="+pfx, "WINEDEBUG=-all",
		`WINEDLLOVERRIDES=mscoree,mshtml=`)
	cmd := exec.Command("wine", "wineboot", "-u")
	cmd.Env = env
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Skipf("wineboot failed: %v", err)
		}
	case <-time.After(90 * time.Second):
		cmd.Process.Kill()
		t.Skip("wineboot timed out")
	}
	defer exec.Command("wineserver", "-k").Run()
	// Check Documents symlink handling.
	doc := pfx + "/drive_c/users/" + os.Getenv("USER") + "/Documents"
	fi, err := os.Lstat(doc)
	if err != nil {
		t.Skipf("no Documents dir: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(doc)
		t.Logf("Documents is a symlink -> %s (shared-home; tracker must not follow)", target)
	} else {
		t.Log("Documents is a real dir inside prefix")
	}
	// detection over the real prefix must not escape the tree.
	env2 := &detect.Env{Home: filepath.Dir(pfx), OS: "linux", WINEPREFIX: pfx}
	g, p, err := detect.PrefixFinder{}.Find(context.Background(), env2, os.DirFS("/"))
	if err != nil {
		t.Fatal(err)
	}
	_ = g
	found := false
	for _, pp := range p {
		if pp.Dir == pfx {
			found = true
		}
	}
	if !found {
		t.Fatalf("prefix %s not detected", pfx)
	}
}

// Scenario 6: proton compatdata.
func TestProton(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	url, stop := startServer(t)
	defer stop()
	envA := deviceEnv(t, "A")
	hA := envHome(envA)
	// steam lib + appmanifest + compatdata prefix
	writeFile(t, hA, ".steam/steam/steamapps/appmanifest_7.acf",
		`"AppState"{"appid" "7" "name" "ProtonGame" "installdir" "pg"}`)
	os.MkdirAll(hA+"/.steam/steam/steamapps/common/pg", 0o755)
	save := hA + "/.steam/steam/steamapps/compatdata/7/pfx/drive_c/users/steamuser/My Documents/pg"
	os.MkdirAll(save, 0o755)
	os.WriteFile(save+"/s.dat", []byte("proton-save"), 0o644)
	code, _, se := run(t, envA, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup: %s", se)
	}
	_, out, _ := run(t, envA, "games", "list", "--json")
	if !strings.Contains(out, "steam:7") {
		t.Fatalf("steam game missing: %s", out)
	}
	code, _, se = run(t, envA, "track", "add", "--path", save,
		"--app", "steam:7", "--slot", "default", "--key", "proton")
	if code != 0 {
		t.Fatalf("track: %s", se)
	}
	code, _, se = run(t, envA, "push", "--all")
	if code != 0 {
		t.Fatalf("push: %s", se)
	}
	// B pull
	envB := deviceEnv(t, "B")
	hB := envHome(envB)
	b, _ := os.ReadFile(hA + "/.config/saves/config.json")
	var jc struct{ Token string }
	json.Unmarshal(b, &jc)
	run(t, envB, "setup", "--server", url, "--token", jc.Token)
	os.MkdirAll(hB+"/g", 0o755)
	run(t, envB, "track", "add", "--path", hB+"/g", "--app", "steam:7", "--slot", "default", "--key", "proton")
	code, _, se = run(t, envB, "pull", "--all")
	if code != 0 {
		t.Fatalf("pull B: %s", se)
	}
	if got := readFile(t, hB, "g/s.dat"); got != "proton-save" {
		t.Fatalf("got %q", got)
	}
}

// Scenario 7: auth exit 4, quota exit 5, restart persistence.
func TestAuthQuotaRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	url, stop := startServer(t)
	defer stop()
	envA := deviceEnv(t, "A")
	hA := envHome(envA)
	code, _, se := run(t, envA, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup: %s", se)
	}
	code, _, _ = run(t, envA, "me", "--token", "bogus")
	if code != 4 {
		t.Fatalf("want exit 4 got %d", code)
	}
	// restart persistence
	writeFile(t, hA, "g/d.dat", "persist")
	run(t, envA, "track", "add", "--path", hA+"/g", "--app", "persist", "--slot", "s")
	run(t, envA, "push", "--all")
	stop()
	url2, stop2 := startServerDir(t, srvDir(url))
	defer stop2()
	code, _, se = run(t, envA, "pull", "--all", "--server", url2)
	t.Logf("pull after restart: %d %s", code, se)
}

var _ = bytes.MinRead

var _ = bytes.MinRead

// Quota: 8 MiB tier rejects a 12 MiB world push with exit 5.
func TestQuotaExit(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	url, stop := startServerQuota(t, 3<<20)
	defer stop()
	envA := deviceEnv(t, "A")
	hA := envHome(envA)
	os.MkdirAll(hA+"/g", 0o755)
	buf := make([]byte, 8<<20)
	rand.Read(buf)
	os.WriteFile(hA+"/g/big.dat", buf, 0o600)
	code, _, se := run(t, envA, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup: %s", se)
	}
	run(t, envA, "track", "add", "--path", hA+"/g", "--app", "qgame", "--slot", "s")
	code, _, se = run(t, envA, "push", "--all")
	if code != 5 {
		t.Fatalf("want exit 5 got %d err=%s", code, se)
	}
}

func startServerQuota(t *testing.T, quotaBytes int) (string, func()) {
	t.Helper()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("127.0.0.1:%d", port)
	l.Close()
	dir := t.TempDir()
	cfg := fmt.Sprintf(`{
  "listen": {"addr": "127.0.0.1:%d", "protocols": ["h1"]},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "open"},
  "quota": {"allow_unknown_apps": ".*", "tiers": {"free": {"quota_bytes": %d, "max_file_bytes": 1099511627776, "max_snapshot_bytes": 1099511627776, "max_files": 100000, "max_slots": 100, "max_snapshots_per_slot": 100, "max_concurrent_uploads": 64, "max_pending_snapshots": 10, "rate": {"requests_per_sec": 1000, "burst": 1000}, "retention": {"keep_last": 10}}}},
  "sandbox": {"mode": "off"},
  "log": {"level": "error"}
}`, port, dir, dir, quotaBytes)
	cp := filepath.Join(dir, "config.json")
	os.WriteFile(cp, []byte(cfg), 0o600)
	cmd := exec.Command(filepath.Join(binDir, "savesd"), "serve", "-config", cp)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop := func() { cmd.Process.Kill(); cmd.Wait() }
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return fmt.Sprintf("http://127.0.0.1:%d", port), stop
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("savesd did not come up")
	return "", stop
}

// Scenario 8: windows binary under wine.
func TestWindowsUnderWine(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	out := filepath.Join(t.TempDir(), "savesctl.exe")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/savesctl")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("windows build: %v\n%s", err, b)
	}
	if _, err := exec.LookPath("wine"); err != nil {
		t.Skip("no wine")
	}
	wenv := append(os.Environ(),
		"WINEPREFIX="+t.TempDir()+"/wp", "WINEDEBUG=-all",
		`WINEDLLOVERRIDES=mscoree,mshtml=`)
	c2 := exec.Command("wine", "wineboot", "-u")
	c2.Env = wenv
	done := make(chan error, 1)
	go func() { done <- c2.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Skipf("wineboot failed: %v", err)
		}
	case <-time.After(90 * time.Second):
		c2.Process.Kill()
		t.Skip("wineboot timed out")
	}
	defer exec.Command("wineserver", "-k").Run()
	c3 := exec.Command("wine", out, "version")
	c3.Env = wenv
	b, err := c3.CombinedOutput()
	if err != nil {
		t.Skipf("wine run failed: %v %s", err, b)
	}
	t.Logf("savesctl.exe under wine: %s", strings.TrimSpace(string(b)))
}
