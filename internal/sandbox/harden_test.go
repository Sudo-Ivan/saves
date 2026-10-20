// SPDX-License-Identifier: 0BSD

package sandbox

import (
	"os"
	"os/exec"
	"testing"
)

func TestHardenChild(t *testing.T) {
	if os.Getenv("SBX_CHILD") == "1" {
		if err := Harden(true); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHardenChild")
	cmd.Env = append(os.Environ(), "SBX_CHILD=1")
	if err := cmd.Run(); err != nil {
		t.Fatalf("child harden failed: %v", err)
	}
}
