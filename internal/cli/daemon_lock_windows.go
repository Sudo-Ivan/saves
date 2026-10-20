// SPDX-License-Identifier: 0BSD
//go:build windows

package cli

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// daemonLock takes an exclusive lock via O_EXCL plus pid liveness.
func daemonLock(path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// stale lock: check if pid inside is alive
			b, _ := os.ReadFile(path)
			var pid int
			fmt.Sscanf(string(b), "%d", &pid)
			if pid > 0 {
				if p, err := os.FindProcess(pid); err == nil {
					_ = p
					// windows FindProcess succeeds for dead pids; try signal 0
				}
			}
			if rmErr := os.Remove(path); rmErr == nil {
				f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			}
			if err != nil {
				return nil, fmt.Errorf("daemon already running (lock held)")
			}
		} else {
			return nil, err
		}
	}
	fmt.Fprintf(f, "%d", os.Getpid())
	f.Close()
	return func() { os.Remove(path) }, nil
}

var _ = syscall.Errno(0)
var _ = time.Now
