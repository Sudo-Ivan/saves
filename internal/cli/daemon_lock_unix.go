// SPDX-License-Identifier: 0BSD
//go:build !windows

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// daemonLock takes an exclusive lock on the file; returns a release.
func daemonLock(path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path chosen by the local user or derived from validated config
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("daemon already running (lock held)")
	}
	return func() { f.Close() }, nil // #nosec G104 -- best effort, error is not actionable
}
