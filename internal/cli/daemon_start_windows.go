// SPDX-License-Identifier: 0BSD
//go:build windows

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// startDetached spawns `savesctl daemon run` detached on windows.
func startDetached(e *Env, exe string, stateDir string) (int, error) {
	dir := filepath.Join(stateDir, "runtime")
	os.MkdirAll(dir, 0o700)
	lock, err := os.OpenFile(filepath.Join(dir, "daemon.lock"),
		os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return 0, fmt.Errorf("daemon already running")
	}
	fmt.Fprintf(lock, "%d", os.Getpid())
	lock.Close()
	cmd := exec.Command(exe, "daemon", "run")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200,
	}
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if devnull != nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := daemonCall(e, "GET", "/status"); err == nil {
			return cmd.Process.Pid, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cmd.Process.Pid, fmt.Errorf("daemon did not answer in 10s")
}
