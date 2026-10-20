// SPDX-License-Identifier: 0BSD
//go:build !linux

package netx

func setBuf(fd uintptr, size int) { _ = fd; _ = size }

// SetBufForTest is a no-op off linux.
func SetBufForTest(fd uintptr, size int) { _ = fd; _ = size }
