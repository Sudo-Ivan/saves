// SPDX-License-Identifier: 0BSD

//go:build !unix

package server

func statfs(string) (free, total uint64, ok bool) { return 0, 0, false }
