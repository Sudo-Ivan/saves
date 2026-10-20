// SPDX-License-Identifier: 0BSD
//go:build linux || darwin

package detect

import (
	"os"
	"syscall"
)

// IsWorldLocked reports whether dir/session.lock holds a write lock.
func IsWorldLocked(dir string) bool {
	f, err := os.OpenFile(dir+"/session.lock", os.O_RDWR, 0) // #nosec G304 -- world dir from detection
	if err != nil {
		return false
	}
	defer f.Close()
	var fl syscall.Flock_t
	fl.Type = syscall.F_WRLCK
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &fl); err != nil {
		return false
	}
	return fl.Type != syscall.F_UNLCK
}

const unixLock = true
