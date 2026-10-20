// SPDX-License-Identifier: 0BSD
//go:build windows

package detect

import (
	"syscall"
)

// IsWorldLocked probes session.lock with an exclusive open.
func IsWorldLocked(dir string) bool {
	p := dir + "\\session.lock"
	pp, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return false
	}
	h, err := syscall.CreateFile(pp, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return true // cannot open: locked or absent
	}
	syscall.Close(h)
	return false
}

const unixLock = false
