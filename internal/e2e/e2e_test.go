// SPDX-License-Identifier: 0BSD

package e2e

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var binDir string

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "e2ebin")
	if err != nil {
		panic(err)
	}
	binDir = dir
	for _, n := range []string{"savesd", "savesctl"} {
		out := filepath.Join(dir, n)
		cmd := exec.Command("go", "build", "-o", out, "./cmd/"+n)
		cmd.Dir = "../.."
		if b, err := cmd.CombinedOutput(); err != nil {
			panic(fmt.Sprintf("build %s: %v\n%s", n, err, b))
		}
	}
	os.Exit(m.Run())
}

// start savesd on a free port.
var srvDataDir string

func startServer(t *testing.T) (url string, stop func()) {
	t.Helper()
	srvDataDir = ""
	return startServerDir(t, "")
}

// startServerDir runs savesd in dir, reusing it for restart tests.
func startServerDir(t *testing.T, dir string) (url string, stop func()) {
	t.Helper()
	srvDataDir = dir
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("127.0.0.1:%d", port)
	l.Close()
	if dir == "" {
		dir = t.TempDir()
	}
	srvDataDir = dir
	cfg := fmt.Sprintf(`{
  "listen": {"addr": "127.0.0.1:%d", "protocols": ["h1"]},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "open"},
  "quota": {"allow_unknown_apps": ".*", "apps": {"conflictgame": {"allow_force": true}, "testgame": {"allow_force": true}, "minecraft-java": {"allow_force": true}}},
  "sandbox": {"mode": "off"},
  "log": {"level": "error"}
}`, port, dir, dir)
	cp := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cp, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(binDir, "savesd"), "serve", "-config", cp)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	url = fmt.Sprintf("http://127.0.0.1:%d", port)
	stop = func() { cmd.Process.Kill(); cmd.Wait() }
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return url, stop
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("savesd did not come up")
	return "", stop
}

// srvDir returns the current server's data dir.
func srvDir(_ string) string { return srvDataDir }

// device env for a fake home.
func deviceEnv(t *testing.T, name string) []string {
	home := t.TempDir()
	return append(os.Environ(),
		"HOME="+home,
		"SAVES_CONFIG_DIR="+home+"/.config/saves",
		"SAVES_STATE_DIR="+home+"/.state/saves",
		"SAVES_CACHE_DIR="+home+"/.cache/saves",
		"XDG_CONFIG_HOME="+home+"/.config",
		"XDG_DATA_HOME="+home+"/.local/share",
		"XDG_STATE_HOME="+home+"/.local/state",
		"XDG_CACHE_HOME="+home+"/.cache",
		"HOME_DIR="+home,
	)
}

func run(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "savesctl"), args...)
	cmd.Env = env
	var sob, seb bytes.Buffer
	cmd.Stdout = &sob
	cmd.Stderr = &seb
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return code, sob.String(), seb.String()
}

// writeFile makes a file under root.
func writeFile(t *testing.T, home, rel, content string) {
	p := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, home, rel string) string {
	b, err := os.ReadFile(filepath.Join(home, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func envHome(env []string) string {
	for _, kv := range env {
		if len(kv) > 9 && kv[:9] == "HOME_DIR=" {
			return kv[9:]
		}
	}
	return ""
}

func TestRoundTrip(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	envA := deviceEnv(t, "A")
	envB := deviceEnv(t, "B")
	hA := envHome(envA)
	hB := envHome(envB)
	// A: setup register, manual track a dir, push
	writeFile(t, hA, "saves/game/save1.dat", "hello world")
	writeFile(t, hA, "saves/game/nested/x.sav", "nested")
	code, out, se := run(t, envA, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup: %d %s", code, se)
	}
	code, _, se = run(t, envA, "track", "add", "--path", hA+"/saves/game", "--app", "testgame", "--slot", "main")
	if code != 0 {
		t.Fatalf("track: %d %s", code, se)
	}
	code, _, se = run(t, envA, "push", "--all")
	t.Logf("push out=%q err=%q", out, se)
	if code != 0 {
		t.Fatalf("push: %d %s", code, se)
	}
	// B: same account (use A's token)
	var token string
	for _, kv := range []string{} {
		_ = kv
	}
	// extract token from A config file
	cfgp := envHome(envA) + "/.config/saves/config.json"
	b, _ := os.ReadFile(cfgp)
	var jc struct{ Token string }
	json.Unmarshal(b, &jc)
	token = jc.Token
	code, _, se = run(t, envB, "setup", "--server", url, "--token", token)
	if code != 0 {
		t.Fatalf("setup B: %d %s", code, se)
	}
	code, _, se = run(t, envB, "track", "add", "--path", hB+"/saves/game", "--app", "testgame", "--slot", "main")
	if code != 0 {
		t.Fatalf("track B: %d %s", code, se)
	}
	code, _, se = run(t, envB, "pull", "--all")
	t.Logf("pull out=%q err=%q", out, se)
	if code != 0 {
		t.Fatalf("pull B: %d %s", code, se)
	}
	if got := readFile(t, hB, "saves/game/save1.dat"); got != "hello world" {
		t.Fatalf("got %q", got)
	}
	if got := readFile(t, hB, "saves/game/nested/x.sav"); got != "nested" {
		t.Fatalf("nested %q", got)
	}
	// wrong token -> exit 4
	envC := append([]string{}, envA...)
	code, _, _ = run(t, envC, "me", "--token", "bogus")
	if code != 4 {
		t.Fatalf("want exit 4 got %d", code)
	}
	// doctor
	code, _, _ = run(t, envB, "doctor")
	if code != 0 && code != 1 {
		t.Fatalf("doctor %d", code)
	}
}

func TestJSONOut(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	env := deviceEnv(t, "A")
	code, _, _ := run(t, env, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup %d", code)
	}
	var out string
	code, out, _ = run(t, env, "me", "--json")
	if code != 0 {
		t.Fatalf("me %d", code)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("bad json %q", out)
	}
}
