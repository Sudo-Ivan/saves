// SPDX-License-Identifier: 0BSD

// Package apispec embeds the OpenAPI document.
package apispec

import _ "embed"

//go:embed openapi.yaml
var spec []byte

// Spec returns the embedded OpenAPI document.
func Spec() []byte { return spec }
