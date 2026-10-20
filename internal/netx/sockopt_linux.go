// SPDX-License-Identifier: 0BSD
//go:build linux

package netx

import "syscall"

func setBuf(fd uintptr, size int) {
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
}

// SetBufForTest exposes setBuf for nettest.
func SetBufForTest(fd uintptr, size int) { setBuf(fd, size) }
