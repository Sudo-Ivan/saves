// SPDX-License-Identifier: 0BSD

package tray

import (
	"errors"
	"os"
	"runtime"
	"strings"
)

// ErrHeadless is returned when no tray-capable session exists.
var ErrHeadless = errors.New("tray: no graphical session (no session bus or display)")

// Headless detects whether a tray can run.
func Headless() bool {
	if runtime.GOOS == "linux" {
		return os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" &&
			os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
	}
	return !strings.EqualFold(os.Getenv("DISPLAY"), "") ||
		(runtime.GOOS != "windows" && runtime.GOOS != "darwin")
}
