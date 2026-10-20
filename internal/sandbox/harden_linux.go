// SPDX-License-Identifier: 0BSD
//go:build linux

package sandbox

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Harden applies process level hardening before Apply.
func Harden(allowRoot bool) error {
	if os.Geteuid() == 0 && !allowRoot {
		return errors.New("sandbox: refusing to run as uid 0; set sandbox.allow_root")
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	syscall.Umask(0o077)
	return nil
}

// NoNewPrivs reports whether PR_GET_NO_NEW_PRIVS is set.
func NoNewPrivs() (bool, error) {
	v, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	if errno != 0 {
		return false, errno
	}
	return v == 1, nil
}
