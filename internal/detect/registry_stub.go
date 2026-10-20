// SPDX-License-Identifier: 0BSD
//go:build !windows

package detect

// NewRegistry returns nil off Windows; tests use fakeRegistry.
func NewRegistry() RegistryReader { return nil }
