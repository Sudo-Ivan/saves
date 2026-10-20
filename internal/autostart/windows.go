// SPDX-License-Identifier: 0BSD
//go:build windows

package autostart

import (
	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func runName(s Spec) string {
	if s.Target == "tray" {
		return "SavesTray"
	}
	return "SavesDaemon"
}

func installWindows(s Spec) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cmd := `"` + s.Exe + `" daemon start`
	if s.Target == "tray" {
		cmd = `"` + s.Exe + `" tray`
	}
	return k.SetStringValue(runName(s), cmd)
}

func uninstallWindows(s Spec) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	_ = k.DeleteValue(runName(s))
	return nil
}

func statusWindows(s Spec) (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false, nil
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runName(s))
	return err == nil, nil
}
