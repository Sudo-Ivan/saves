// SPDX-License-Identifier: 0BSD
//go:build linux || darwin

package detect

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// Lock detection via subprocess holding a fcntl lock.
func TestIsWorldLocked(t *testing.T) {
	if os.Getenv("SAVES_LOCKHELPER") == "1" {
		dir := os.Getenv("SAVES_LOCKDIR")
		f, _ := os.OpenFile(dir+"/session.lock", os.O_RDWR|os.O_CREATE, 0o600)
		var fl syscall.Flock_t
		fl.Type = syscall.F_WRLCK
		fl.Whence = 0
		syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &fl)
		os.Stdout.WriteString("locked")
		select {}
	}
	if !unixLock {
		t.Skip("unix only")
	}
	dir := t.TempDir()
	if IsWorldLocked(dir) {
		t.Fatal("unlocked dir reported locked")
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestIsWorldLocked")
	cmd.Env = append(os.Environ(), "SAVES_LOCKHELPER=1", "SAVES_LOCKDIR="+dir)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	buf := make([]byte, 16)
	out.Read(buf)
	if !IsWorldLocked(dir) {
		t.Fatal("locked dir not detected")
	}
	cmd.Process.Kill()
	cmd.Wait()
}
