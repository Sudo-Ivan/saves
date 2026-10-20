// SPDX-License-Identifier: 0BSD

// Package opener opens files and URLs via the platform handler.
package opener

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner executes a command; injectable for tests.
var Runner = func(name string, args ...string) error {
	return exec.Command(name, args...).Start()
}

var schemes = map[string]bool{"http": true, "https": true, "file": true}

// Open dispatches path or URL to the OS handler.
func Open(target string) error {
	if strings.Contains(target, "\n") || strings.Contains(target, "\r") {
		return fmt.Errorf("opener: newline in target")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("opener: target looks like a flag")
	}
	if i := strings.Index(target, "://"); i >= 0 {
		if !schemes[strings.ToLower(target[:i])] {
			return fmt.Errorf("opener: scheme %q not allowed", target[:i])
		}
		return openCmd()(target)
	}
	// Local path: reject flag-like and must exist.
	if _, err := os.Stat(target); err != nil {
		return err
	}
	return openCmd()(target)
}

func openCmd() func(string) error {
	return func(t string) error { return Runner("xdg-open", t) }
}
