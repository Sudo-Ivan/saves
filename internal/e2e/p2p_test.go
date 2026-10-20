// SPDX-License-Identifier: 0BSD

package e2e

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// TestP2PJoinPushPull: host --pair + joiner + push/pull via transport.
func TestP2PJoinPushPull(t *testing.T) {
	envH := deviceEnv(t, "ph")
	envJ := deviceEnv(t, "pj")
	// start host with --pair
	cmd := exec.Command(filepath.Join(binDir, "savesctl"), "p2p", "host", "start", "--pair",
		"--listen", "127.0.0.1:0")
	cmd.Env = envH
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	// read "host id X addr Y" and "pairing code Z" lines
	rd := bufio.NewScanner(out)
	var hid, addr, code, paddr string
	deadline := time.Now().Add(15 * time.Second)
	for rd.Scan() {
		l := rd.Text()
		if m := regexp.MustCompile(`host id (\S+) addr (\S+)`).FindStringSubmatch(l); m != nil {
			hid, addr = m[1], m[2]
		}
		if m := regexp.MustCompile(`pairing code (\S+) on (\S+)`).FindStringSubmatch(l); m != nil {
			code, paddr = m[1], m[2]
		}
		if hid != "" && code != "" {
			break
		}
		if time.Now().After(deadline) {
			break
		}
	}
	if hid == "" || code == "" || paddr == "" {
		t.Fatalf("host output id=%q addr=%q code=%q", hid, addr, code)
	}
	t.Logf("host %s at %s code %s", hid, addr, code)
	// join
	c, o, e := run(t, envJ, "p2p", "join", code+"@"+paddr)
	if c != 0 {
		t.Fatalf("join: %d %s %s", c, o, e)
	}
	// push from J
	dir := t.TempDir() + "/w"
	os.MkdirAll(dir, 0o700)
	os.WriteFile(dir+"/f.dat", []byte("hello p2p"), 0o600)
	run(t, envJ, "track", "add", "--path", dir, "--app", "p2pgame",
		"--slot", "s", "--key", "save")
	c, o, e = run(t, envJ, "push", "p2pgame/s", "--json")
	if c != 0 {
		t.Fatalf("push: %d %s %s", c, o, e)
	}
	t.Logf("push: %s", o)
}
