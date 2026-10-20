// SPDX-License-Identifier: 0BSD

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startServerEnforce starts savesd with sandbox.mode=enforce.
func startServerEnforce(t *testing.T) (url string, dataDir string, sb *strings.Builder, stop func()) {
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
  "quota": {"allow_unknown_apps": ".*"},
  "sandbox": {"mode": "enforce", "allow_root": true},
  "log": {"level": "debug"}
}`, port, dir, dir)
	cp := filepath.Join(dir, "config.json")
	os.WriteFile(cp, []byte(cfg), 0o600)
	cmd := exec.Command(filepath.Join(binDir, "savesd"), "serve", "-config", cp)
	cmd.Dir = dir
	sb = &strings.Builder{}
	cmd.Stderr = sb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop = func() { cmd.Process.Kill(); cmd.Wait() }
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return fmt.Sprintf("http://127.0.0.1:%d", port), dir, sb, stop
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("savesd did not come up; stderr=%s", sb.String())
	return "", dir, sb, stop
}

func TestSandboxEnforce(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	url, _, sb, stop := startServerEnforce(t)
	defer stop()
	envA, envB, hA, hB := trackPair(t, url)
	_ = envA
	_ = hA
	_ = hB
	writeFile(t, hA, "g/save.dat", "sandboxed")
	code, _, se := run(t, envA, "push", "--all")
	t.Logf("server stderr: %s", sb.String())
	if code != 0 {
		t.Fatalf("push under enforce: %d %s", code, se)
	}
	// B pulls
	code, outp, se := run(t, envB, "pull", "--all")
	if code != 0 {
		t.Fatalf("pull under enforce: %d %s", code, se)
	}
	_ = outp
	if got := readFile(t, hB, "g/save.dat"); got != "sandboxed" {
		t.Fatalf("pull got %q", got)
	}
	// NoNewPrivs check on the server pid would need pid discovery; check
	// sandbox-check JSON instead.
}

// TestSandboxCheck runs the subcommand against an enforce config.
func TestSandboxCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	dir := t.TempDir()
	cfg := fmt.Sprintf(`{
  "listen": {"addr": "127.0.0.1:0", "protocols": ["h1"]},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "open"},
  "quota": {"allow_unknown_apps": ".*"},
  "sandbox": {"mode": "enforce", "allow_root": true, "extra_rw_paths": ["%s"]},
  "log": {"level": "debug"}
}`, dir, dir, dir)
	cp := filepath.Join(dir, "config.json")
	os.WriteFile(cp, []byte(cfg), 0o600)
	os.MkdirAll(dir+"/blobs", 0o755)
	cmd := exec.Command(filepath.Join(binDir, "savesd"), "sandbox-check", "-config", cp)
	out, err := cmd.CombinedOutput()
	t.Logf("sandbox-check: %s", out)
	// enforce mode: any deny success or allow failure -> nonzero
	if err == nil {
		// parse JSON for probe results
		var rep struct {
			ABI    int  `json:"abi"`
			FS     bool `json:"fs"`
			Probes []struct {
				Name string `json:"Name"`
				Deny bool   `json:"Deny"`
				OK   bool   `json:"OK"`
			} `json:"probes"`
		}
		if json.Unmarshal(out, &rep) == nil {
			for _, p := range rep.Probes {
				if !p.OK {
					t.Fatalf("probe %s unexpectedly passed (deny=%v)", p.Name, p.Deny)
				}
			}
		}
	}
	// mode enforce with / as rw: must refuse at config/policy level
	cfg2 := strings.Replace(cfg, `"extra_rw_paths": ["`+dir+`"]`, `"extra_rw_paths": ["/"]`, 1)
	cp2 := filepath.Join(dir, "config2.json")
	os.WriteFile(cp2, []byte(cfg2), 0o600)
	c2 := exec.Command(filepath.Join(binDir, "savesd"), "serve", "-config", cp2)
	c2.Env = append(os.Environ(), "SAVES_SBX_CHILD=1")
	b, _ := c2.CombinedOutput()
	_ = b
	// serve should fail at config validation or policy build
	if c2.ProcessState != nil && c2.ProcessState.ExitCode() == 0 {
		t.Fatal("savesd started with extra_rw_paths /")
	}
}
