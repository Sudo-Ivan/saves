// SPDX-License-Identifier: 0BSD

//go:build unix

package server

import "syscall"

func statfs(path string) (free, total uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	bs := uint64(st.Bsize)                                      // #nosec G115 -- block size is positive
	return uint64(st.Bavail) * bs, uint64(st.Blocks) * bs, true // #nosec G115 -- counts are unsigned in practice
}
