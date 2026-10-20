// SPDX-License-Identifier: 0BSD

package api

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Path limits shared by clients and servers so a manifest restores safely
// on any operating system.
const (
	maxPathBytes      = 1024
	maxComponentBytes = 255
	maxPathDepth      = 64
)

var errPath = errors.New("invalid path")

// CleanPath normalizes separators, removes redundant slashes, and resolves
// dot components without touching the filesystem. It never escapes above
// the root. The result is validated by ValidatePath.
func CleanPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	parts := make([]string, 0, strings.Count(p, "/")+1)
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		default:
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, "/")
}

// ValidatePath checks p against the portable path rules. maxDepth values
// below 1 or above 64 are clamped to 64.
func ValidatePath(p string, maxDepth int) error {
	if maxDepth < 1 || maxDepth > maxPathDepth {
		maxDepth = maxPathDepth
	}
	if p == "" {
		return fmt.Errorf("%w: empty", errPath)
	}
	if !utf8.ValidString(p) {
		return fmt.Errorf("%w: not valid UTF-8", errPath)
	}
	if len(p) > maxPathBytes {
		return fmt.Errorf("%w: exceeds %d bytes", errPath, maxPathBytes)
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("%w: leading or trailing slash", errPath)
	}
	parts := strings.Split(p, "/")
	if len(parts) > maxDepth {
		return fmt.Errorf("%w: depth %d exceeds %d", errPath, len(parts), maxDepth)
	}
	for _, c := range parts {
		if err := validateComponent(c); err != nil {
			return err
		}
	}
	return nil
}

func validateComponent(c string) error {
	if c == "" {
		return fmt.Errorf("%w: empty component", errPath)
	}
	if c == "." || c == ".." {
		return fmt.Errorf("%w: dot component %q", errPath, c)
	}
	if len(c) > maxComponentBytes {
		return fmt.Errorf("%w: component exceeds %d bytes", errPath, maxComponentBytes)
	}
	if c[len(c)-1] == '.' || c[len(c)-1] == ' ' {
		return fmt.Errorf("%w: component ends in dot or space", errPath)
	}
	for _, r := range c {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("%w: control character", errPath)
		case r == '\\':
			return fmt.Errorf("%w: backslash", errPath)
		case strings.ContainsRune(`<>:"|?*`, r):
			return fmt.Errorf("%w: forbidden character %q", errPath, r)
		}
	}
	if isWindowsDevice(c) {
		return fmt.Errorf("%w: reserved device name %q", errPath, c)
	}
	return nil
}

var deviceNames = map[string]struct{}{
	"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
	"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {},
	"COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
	"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {},
	"LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
}

func isWindowsDevice(c string) bool {
	base := c
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(base)
	_, ok := deviceNames[base]
	return ok
}

var appIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

// ValidateAppID checks an application identifier.
func ValidateAppID(id string) error {
	if !appIDRe.MatchString(id) {
		return fmt.Errorf("invalid app id %q: want ^[a-z0-9][a-z0-9._:-]{0,63}$", id)
	}
	return nil
}

// ValidateSlotName checks a slot name: UTF-8, at most 128 bytes, no
// control characters and no slashes.
func ValidateSlotName(s string) error {
	if s == "" {
		return errors.New("invalid slot name: empty")
	}
	if len(s) > 128 {
		return errors.New("invalid slot name: exceeds 128 bytes")
	}
	if !utf8.ValidString(s) {
		return errors.New("invalid slot name: not valid UTF-8")
	}
	for _, r := range s {
		if r == '/' || r == '\\' {
			return fmt.Errorf("invalid slot name %q: slash", s)
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("invalid slot name %q: control character", s)
		}
	}
	return nil
}
