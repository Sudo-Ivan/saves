// SPDX-License-Identifier: 0BSD
//go:build !linux

package sandbox

import "errors"

// Apply reports unsupported off linux.
func Apply(p *Policy, mode string) (Report, error) {
	if mode == "enforce" {
		return Report{Mode: mode}, errors.New("sandbox: Landlock unsupported on this platform; use mode best-effort or off")
	}
	return Report{Mode: mode}, nil
}
