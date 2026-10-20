//go:build !windows

// SPDX-License-Identifier: 0BSD

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// startDetached spawns `savesctl daemon run` detached via setsid.
func startDetached(e *Env, exe string, stateDir string) (int, error) {
	os.MkdirAll(filepath.Join(stateDir, "runtime"), 0o700)
	cmd := exec.Command(exe, "daemon", "run")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	cmd.Stdin = devnull
	lf2, _ := os.OpenFile(filepath.Join(stateDir, "runtime", "daemon.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if lf2 != nil {
		cmd.Stdout, cmd.Stderr = lf2, lf2
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	// The lock file is inherited by the child; released when it exits.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := daemonCall(e, "GET", "/status"); err == nil {
			return cmd.Process.Pid, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cmd.Process.Pid, fmt.Errorf("daemon did not answer in 10s")
}
