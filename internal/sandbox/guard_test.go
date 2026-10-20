// SPDX-License-Identifier: 0BSD

package sandbox_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Guard: no code outside netx should create raw net listeners or
// default http transports.
func TestMPTCPGuard(t *testing.T) {
	skip := map[string]bool{
		"internal/netx": true, "internal/netx/nettest": true,
		"internal/cli": true, "internal/detect": true, "internal/daemon": true, "internal/syncctl": true,
		"cmd/savesctl": true, "pkg/client": true, "internal/sandbox": true,
		"internal/e2e": true, "internal/testserver": true,
	}
	var bad []string
	filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := filepath.ToSlash(p)
		if !strings.Contains(rel, "/internal/") && !strings.Contains(rel, "/cmd/") {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		for k := range skip {
			if strings.HasPrefix(filepath.ToSlash(p), "../"+k) || strings.Contains(p, k+"/") {
				return nil
			}
		}
		b, _ := os.ReadFile(p)
		for _, pat := range []string{"net.Listen(", "net.ListenTCP(", "net.Dial(",
			"&net.Dialer{", "http.DefaultTransport", "http.DefaultClient",
			"&http.Client{", "&http.Transport{"} {
			if strings.Contains(string(b), pat) && !strings.Contains(string(b), "netx.") {
				bad = append(bad, p+":"+pat)
			}
		}
		_ = parser.ParseFile
		return nil
	})
	if len(bad) > 0 {
		t.Fatalf("non-netx transports: %v", bad)
	}
}

var _ = token.NewFileSet
