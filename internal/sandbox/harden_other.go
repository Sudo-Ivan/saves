// SPDX-License-Identifier: 0BSD
//go:build !linux

package sandbox

// Harden is a no-op off linux.
func Harden(allowRoot bool) error { return nil }

// NoNewPrivs reports false off linux.
func NoNewPrivs() (bool, error) { return false, nil }
