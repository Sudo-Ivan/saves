// SPDX-License-Identifier: 0BSD

// Package autostart installs per-user startup entries for the daemon
// (systemd user unit on Linux, HKCU Run on Windows) and the tray (XDG
// autostart desktop file / HKCU Run).
package autostart

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Spec describes one install.
type Spec struct {
	Target    string // daemon or tray
	Exe       string
	ConfigDir string
	StateDir  string
	CacheDir  string
	RWPaths   []string
}

// ErrBadExe is returned for missing or relative executables.
var ErrBadExe = errors.New("autostart: executable must be an absolute existing path")

func checkExe(exe string) error {
	if !filepath.IsAbs(exe) {
		return ErrBadExe
	}
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		return ErrBadExe
	}
	return nil
}

// Install writes the startup entry for target.
func Install(s Spec) error {
	if err := checkExe(s.Exe); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return installWindows(s)
	}
	return installLinux(s)
}

// Uninstall removes the startup entry.
func Uninstall(s Spec) error {
	if runtime.GOOS == "windows" {
		return uninstallWindows(s)
	}
	return uninstallLinux(s)
}

// Status reports whether the entry exists.
func Status(s Spec) (bool, error) {
	if runtime.GOOS == "windows" {
		return statusWindows(s)
	}
	return statusLinux(s)
}

func unitPath(cfgDir string) string {
	return filepath.Join(cfgDir, "systemd", "user", "saves.service")
}

func desktopPath(cfgDir string) string {
	return filepath.Join(cfgDir, "autostart", "saves-tray.desktop")
}

// unitFile renders the systemd unit.
func unitFile(s Spec) string {
	rw := "ReadWritePaths=" + s.ConfigDir + " " + s.StateDir + " " + s.CacheDir
	for _, p := range s.RWPaths {
		rw += " " + p
	}
	return fmt.Sprintf(`[Unit]
Description=saves sync daemon

[Service]
Type=simple
ExecStart=%s daemon run
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
%s

[Install]
WantedBy=default.target
`, s.Exe, rw)
}

// desktopFile renders the XDG autostart desktop entry.
func desktopFile(s Spec) string {
	return fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=saves tray
Exec=%s tray
X-GNOME-Autostart-enabled=true
`, s.Exe)
}

func installLinux(s Spec) error {
	if s.Target == "tray" {
		p := desktopPath(s.ConfigDir)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, []byte(desktopFile(s)), 0o644)
	}
	p := unitPath(s.ConfigDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(unitFile(s)), 0o644); err != nil {
		return err
	}
	return nil
}

func uninstallLinux(s Spec) error {
	p := unitPath(s.ConfigDir)
	if s.Target == "tray" {
		p = desktopPath(s.ConfigDir)
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func statusLinux(s Spec) (bool, error) {
	p := unitPath(s.ConfigDir)
	if s.Target == "tray" {
		p = desktopPath(s.ConfigDir)
	}
	_, err := os.Stat(p)
	return err == nil, nil
}
