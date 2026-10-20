// SPDX-License-Identifier: 0BSD
//go:build !windows

package autostart

func installWindows(s Spec) error        { return nil }
func uninstallWindows(s Spec) error      { return nil }
func statusWindows(s Spec) (bool, error) { return false, nil }
