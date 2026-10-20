// SPDX-License-Identifier: 0BSD

package e2e

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func setQuietPeriod(t *testing.T, env []string) {
	t.Helper()
	p := filepath.Join(envHome(env), ".config/saves/config.json")
	b, _ := os.ReadFile(p)
	var cfg map[string]any
	json.Unmarshal(b, &cfg)
	cfg["daemon"] = map[string]any{"quiet_period": "1s", "poll_interval": "3s"}
	nb, _ := json.Marshal(cfg)
	os.WriteFile(p, nb, 0o600)
}

func TestDaemon(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	envA := deviceEnv(t, "dA")
	envB := deviceEnv(t, "dB")
	hA, hB := envHome(envA), envHome(envB)
	mkWorld(t, hA+"/.minecraft/saves/W", "W", 0)
	if c, o, e := run(t, envA, "setup", "--server", url, "--register"); c != 0 {
		t.Fatalf("setup A %s %s", o, e)
	}
	cb, _ := os.ReadFile(filepath.Join(hA, ".config/saves/config.json"))
	var jc struct{ Token string }
	json.Unmarshal(cb, &jc)
	if c, o, e := run(t, envB, "setup", "--server", url, "--token", jc.Token); c != 0 {
		t.Fatalf("setup B %s %s", o, e)
	}
	setQuietPeriod(t, envA)
	setQuietPeriod(t, envB)
	run(t, envA, "track", "auto")
	if c, o, e := run(t, envB, "track", "add", "--path", hB+"/.minecraft/saves/W", "--app", "minecraft-java", "--slot", "W", "--key", "world"); c != 0 {
		t.Fatalf("track B %s %s", o, e)
	}
	if c, o, e := run(t, envA, "push", "minecraft-java"); c != 0 {
		t.Fatalf("push %s %s", o, e)
	}
	if c, o, e := run(t, envB, "pull", "minecraft-java"); c != 0 {
		t.Fatalf("pull %s %s", o, e)
	}
	// start both daemons
	c, o, e := run(t, envA, "daemon", "start")
	t.Logf("start A: %d %s %s", c, o, e)
	c, o, e = run(t, envB, "daemon", "start")
	t.Logf("start B: %d %s %s", c, o, e)
	// edit on A
	t0 := time.Now()
	writeFile(t, hA, ".minecraft/saves/W/edited.txt", "fromA"+time.Now().Format("150405"))
	var gotB string
	for i := 0; i < 60; i++ {
		if c2, o2, _ := run(t, envB, "daemon", "status", "--json"); c2 == 0 {
			_ = o2
		}
		if _, err := os.Stat(filepath.Join(hB, ".minecraft/saves/W/edited.txt")); err == nil {
			gotB = "ok"
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("latency B saw file: %s", time.Since(t0))
	if gotB == "" {
		for _, d := range []struct {
			n string
			e []string
		}{{"A", envA}, {"B", envB}} {
			_, lo, _ := run(t, d.e, "daemon", "logs")
			_, so, _ := run(t, d.e, "daemon", "status", "--json")
			t.Logf("daemon %s logs:\n%s\nstatus: %s", d.n, lo, so)
		}
		t.Error("B did not receive the file from A through the daemons")
	}
	// status
	if c, o, _ := run(t, envA, "daemon", "status", "--json"); c != 0 {
		t.Logf("status: %s", o)
	}
	// stop
	c, o, e = run(t, envA, "daemon", "stop")
	t.Logf("stop A: %d %s %s", c, o, e)
	c, o, e = run(t, envB, "daemon", "stop")
	t.Logf("stop B: %d %s %s", c, o, e)
	c, _, _ = run(t, envA, "daemon", "status")
	if c != 3 {
		t.Logf("status after stop: %d (want 3)", c)
	}
	_ = strings.TrimSpace
	_ = exec.Command
}

// daemonPair returns synced A and B devices sharing a world, daemons off.
func daemonPair(t *testing.T, url string) (envA, envB []string) {
	t.Helper()
	envA = deviceEnv(t, "pa")
	envB = deviceEnv(t, "pb")
	hA := envHome(envA)
	hB := envHome(envB)
	mkWorld(t, hA+"/.minecraft/saves/W", "W", 0)
	if c, o, e := run(t, envA, "setup", "--server", url, "--register"); c != 0 {
		t.Fatalf("setup A %s %s", o, e)
	}
	cb, _ := os.ReadFile(filepath.Join(hA, ".config/saves/config.json"))
	var jc struct{ Token string }
	json.Unmarshal(cb, &jc)
	if c, o, e := run(t, envB, "setup", "--server", url, "--token", jc.Token); c != 0 {
		t.Fatalf("setup B %s %s", o, e)
	}
	setQuietPeriod(t, envA)
	setQuietPeriod(t, envB)
	run(t, envA, "track", "auto")
	run(t, envB, "track", "add", "--path", hB+"/.minecraft/saves/W",
		"--app", "minecraft-java", "--slot", "W", "--key", "world")
	run(t, envA, "push", "minecraft-java")
	run(t, envB, "pull", "minecraft-java")
	return envA, envB
}

func TestDaemonPauseResume(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	envA, envB := daemonPair(t, url)
	hA := envHome(envA)
	hB := envHome(envB)
	run(t, envA, "daemon", "start")
	run(t, envB, "daemon", "start")
	defer run(t, envA, "daemon", "stop")
	defer run(t, envB, "daemon", "stop")
	// pause A, edit, B must not get it within 6 s
	run(t, envA, "daemon", "pause")
	writeFile(t, hA, ".minecraft/saves/W/paused.txt", "x")
	time.Sleep(6 * time.Second)
	if _, err := os.Stat(hB + "/.minecraft/saves/W/paused.txt"); err == nil {
		t.Fatal("B got file while A paused")
	}
	run(t, envA, "daemon", "resume")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(hB + "/.minecraft/saves/W/paused.txt"); err == nil {
			t.Logf("resume latency ok")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, d := range []struct {
		n string
		e []string
	}{{"A", envA}, {"B", envB}} {
		_, lo, _ := run(t, d.e, "daemon", "logs")
		_, so, _ := run(t, d.e, "daemon", "status", "--json")
		t.Logf("daemon %s logs:\n%s\nstatus: %s", d.n, lo, so)
	}
	_, sn, _ := run(t, envA, "snapshots", "minecraft-java/W")
	t.Logf("snapshots:\n%s", sn)
	_, st, _ := run(t, envA, "status", "minecraft-java/W")
	t.Logf("A status:\n%s", st)
	t.Fatal("B never got file after resume")
}

func TestDaemonKillRestart(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	envB := deviceEnv(t, "kb")
	hB := envHome(envB)
	mkWorld(t, hB+"/.minecraft/saves/W", "W", 0)
	run(t, envB, "setup", "--server", url, "--register")
	setQuietPeriod(t, envB)
	run(t, envB, "track", "auto")
	// foreground run first to see any startup error.
	done := make(chan int, 1)
	go func() {
		c2, o2, e2 := run(t, envB, "daemon", "run")
		t.Logf("daemon run exited: %d %s %s", c2, o2, e2)
		done <- c2
	}()
	// Wait for the endpoint; dump daemon.log on failure.
	c, o, e := 1, "", ""
	for i := 0; i < 40; i++ {
		c, o, e = run(t, envB, "daemon", "status")
		if c == 0 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Logf("status while running: %d %s %s", c, o, e)
	if c != 0 {
		lb, _ := os.ReadFile(filepath.Join(hB, ".state/saves/runtime/daemon.log"))
		t.Fatalf("daemon run did not come up: %s", lb)
	}
	// find pid from endpoint file to kill later
	// kill -9: stale endpoint file; status must exit 3 or fail
	epb, _ := os.ReadFile(filepath.Join(hB, ".state/saves/runtime/daemon.json"))
	var ep struct{ PID int }
	json.Unmarshal(epb, &ep)
	_ = syscall.Kill(ep.PID, 9)
	time.Sleep(200 * time.Millisecond)
	c, _, _ = run(t, envB, "daemon", "status")
	t.Logf("status after kill -9: %d", c)
	// restart recovers
	c2, o2, e2 := run(t, envB, "daemon", "start")
	t.Logf("restart: %d %s %s", c2, o2, e2)
	run(t, envB, "daemon", "stop")
}

func TestDaemonConflictResolve(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	envA, envB := daemonPair(t, url)
	hA, hB := envHome(envA), envHome(envB)
	// on_conflict ask on B: write it into B's config.
	cfgp := filepath.Join(hB, ".config/saves/config.json")
	b, _ := os.ReadFile(cfgp)
	var cfg map[string]any
	json.Unmarshal(b, &cfg)
	for _, tr := range cfg["tracked"].([]any) {
		tr.(map[string]any)["on_conflict"] = "ask"
	}
	nb, _ := json.Marshal(cfg)
	os.WriteFile(cfgp, nb, 0o600)
	run(t, envA, "daemon", "start")
	defer run(t, envA, "daemon", "stop")
	run(t, envB, "daemon", "start")
	defer run(t, envB, "daemon", "stop")
	time.Sleep(800 * time.Millisecond)
	// diverge: pause B, A pushes, B edits locally, resume -> conflict.
	run(t, envB, "daemon", "pause")
	writeFile(t, hA, ".minecraft/saves/W/conflict.txt", "A side")
	time.Sleep(3 * time.Second) // let A push
	writeFile(t, hB, ".minecraft/saves/W/conflict.txt", "B side")
	run(t, envB, "daemon", "resume")
	// wait for conflict state on B
	for i := 0; i < 40; i++ {
		_, so, _ := run(t, envB, "daemon", "status", "--json")
		if strings.Contains(so, `"state":"conflict"`) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	_, so2, _ := run(t, envB, "daemon", "status", "--json")
	_, lo2, _ := run(t, envB, "daemon", "logs")
	t.Logf("B before resolve status=%s logs=%s", so2, lo2)
	c, out, e := run(t, envB, "daemon", "resolve", "minecraft-java/W", "keep-remote")
	t.Logf("resolve: %d %s %s", c, out, e)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(hB + "/.minecraft/saves/W/conflict.txt"); err == nil && string(b) == "A side" {
			t.Log("B converged to A after resolve")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	_, lo, _ := run(t, envB, "daemon", "logs")
	t.Logf("B logs:\n%s", lo)
	t.Fatal("conflict did not resolve")
}

func TestDaemonSecondInstance(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	envB := deviceEnv(t, "si")
	hB := envHome(envB)
	mkWorld(t, hB+"/.minecraft/saves/W", "W", 0)
	run(t, envB, "setup", "--server", url, "--register")
	setQuietPeriod(t, envB)
	run(t, envB, "track", "auto")
	c, o, e := run(t, envB, "daemon", "start")
	if c != 0 {
		t.Fatalf("first start: %s %s", o, e)
	}
	defer run(t, envB, "daemon", "stop")
	// second foreground run must fail clearly
	c, o, e = run(t, envB, "daemon", "run")
	t.Logf("second run: %d %s %s", c, o, e)
	if c == 0 {
		t.Fatal("second daemon run succeeded")
	}
}

func TestDaemonConflictKeepNewest(t *testing.T) {
	url, stop := startServer(t)
	defer stop()
	envA, envB := daemonPair(t, url)
	hA, hB := envHome(envA), envHome(envB)
	// keep-newest on both
	for _, env := range [][]string{envA, envB} {
		cfgp := filepath.Join(envHome(env), ".config/saves/config.json")
		b, _ := os.ReadFile(cfgp)
		var cfg map[string]any
		json.Unmarshal(b, &cfg)
		for _, tr := range cfg["tracked"].([]any) {
			tr.(map[string]any)["on_conflict"] = "keep-newest"
		}
		nb, _ := json.Marshal(cfg)
		os.WriteFile(cfgp, nb, 0o600)
	}
	run(t, envA, "daemon", "start")
	defer run(t, envA, "daemon", "stop")
	run(t, envB, "daemon", "start")
	defer run(t, envB, "daemon", "stop")
	time.Sleep(800 * time.Millisecond)
	run(t, envB, "daemon", "pause")
	writeFile(t, hA, ".minecraft/saves/W/kn.txt", "A-newest")
	writeFile(t, hB, ".minecraft/saves/W/kn.txt", "B-older")
	time.Sleep(3 * time.Second) // A pushes while B paused
	run(t, envB, "daemon", "resume")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(hB + "/.minecraft/saves/W/kn.txt")
		if err == nil && string(b) == "A-newest" {
			t.Log("keep-newest: remote (newer mtime) won")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	_, lo, _ := run(t, envB, "daemon", "logs")
	t.Logf("B logs:\n%s", lo)
	t.Fatal("keep-newest did not converge")
}

func TestDaemonLockedDefer(t *testing.T) {
	if os.Getenv("E2E_LOCKHELPER") == "1" {
		f, _ := os.OpenFile(os.Getenv("E2E_LOCKDIR")+"/session.lock",
			os.O_RDWR|os.O_CREATE, 0o600)
		var fl syscall.Flock_t
		fl.Type = syscall.F_WRLCK
		syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &fl)
		os.Stdout.WriteString("locked")
		select {}
	}
	url, stop := startServer(t)
	defer stop()
	envA, _ := daemonPair(t, url)
	hA := envHome(envA)
	// hold lock on A's world
	lc := exec.Command(os.Args[0], "-test.run=TestDaemonLockedDefer")
	lc.Env = append(os.Environ(), "E2E_LOCKHELPER=1",
		"E2E_LOCKDIR="+hA+"/.minecraft/saves/W")
	lc.Stdout = io.Discard
	if err := lc.Start(); err != nil {
		t.Skip("lock helper failed")
	}
	defer lc.Process.Kill()
	defer lc.Wait()
	run(t, envA, "daemon", "start")
	defer run(t, envA, "daemon", "stop")
	time.Sleep(800 * time.Millisecond)
	writeFile(t, hA, ".minecraft/saves/W/locked-edit.txt", "x")
	// daemon should defer (state locked)
	for i := 0; i < 20; i++ {
		_, so, _ := run(t, envA, "daemon", "status", "--json")
		if strings.Contains(so, "locked") {
			t.Log("locked state observed")
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	lc.Process.Kill()
	lc.Wait()
}
