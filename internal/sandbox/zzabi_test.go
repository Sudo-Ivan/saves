// SPDX-License-Identifier: 0BSD

package sandbox

import (
	"os"
	"os/exec"
	"testing"
)

// Probe runs Apply in a subprocess and reports what the kernel enforced.
func TestProbe(t *testing.T) {
	if os.Getenv("SBX_PROBE") == "1" {
		p := &Policy{RODirs: []string{"/etc"}, RWDirs: []string{os.TempDir()}}
		r, err := Apply(p, "best-effort")
		if err != nil {
			os.Exit(2)
		}
		if !r.FS {
			os.Exit(3)
		}
		if _, err := os.Stat("/etc/shadow"); err != nil {
			os.Exit(0) // denied: sandbox works
		}
		os.Exit(4)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestProbe")
	cmd.Env = append(os.Environ(), "SBX_PROBE=1")
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 0 {
		return
	}
	if err == nil {
		t.Fatal("shadow was readable inside sandbox")
	}
}
