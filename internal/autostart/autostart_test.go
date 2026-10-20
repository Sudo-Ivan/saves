// SPDX-License-Identifier: 0BSD

package autostart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxFiles(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "savesctl")
	os.WriteFile(exe, []byte("x"), 0o755)
	cfg := t.TempDir()
	spec := Spec{Target: "daemon", Exe: exe,
		ConfigDir: cfg, StateDir: t.TempDir(), CacheDir: t.TempDir()}
	if err := Install(spec); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(unitPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "NoNewPrivileges") || !strings.Contains(string(b), exe+" daemon run") {
		t.Fatal("unit contents wrong")
	}
	if ok, _ := Status(spec); !ok {
		t.Fatal("status false")
	}
	if err := Uninstall(spec); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Status(spec); ok {
		t.Fatal("still installed")
	}
	// tray
	spec.Target = "tray"
	if err := Install(spec); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(desktopPath(cfg))
	if !strings.Contains(string(b), "X-GNOME-Autostart-enabled") {
		t.Fatal("desktop wrong")
	}
	if err := Install(Spec{Exe: "relative/exe"}); err != ErrBadExe {
		t.Fatal("relative exe accepted")
	}
}
