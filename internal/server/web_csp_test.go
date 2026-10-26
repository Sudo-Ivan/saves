// SPDX-License-Identifier: 0BSD

package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoInlineCode ensures no template ships inline script, style, or
// event handler attributes.
func TestNoInlineCode(t *testing.T) {
	bad := regexp.MustCompile(`<style|\sstyle=|\son[a-z]+=`)
	files, err := filepath.Glob("webui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if m := bad.FindString(s); m != "" {
			t.Fatalf("%s: forbidden inline code %q", f, m)
		}
		for _, m := range regexp.MustCompile(`<script[^>]*>`).FindAllString(s, -1) {
			if !strings.HasPrefix(m, "<script src=") {
				t.Fatalf("%s: script without src %q", f, m)
			}
		}
	}
}
