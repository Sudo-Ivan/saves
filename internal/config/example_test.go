// SPDX-License-Identifier: 0BSD

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/config"
)

// TestExampleConfigsLoad loads deploy/config/*.json through config.Load,
// substituting *_file secret references with temp files.
func TestExampleConfigsLoad(t *testing.T) {
	for _, f := range []string{"small", "public", "ha"} {
		b, err := os.ReadFile("../../deploy/config/" + f + ".json")
		if err != nil {
			t.Fatal(err)
		}
		tmp := t.TempDir()
		// every *_file reference is satisfied with a dummy file.
		var out strings.Builder
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.Index(line, "_file\":"); i >= 0 {
				lq := strings.LastIndex(line, "\"")
				fq := strings.LastIndex(line[:lq], "\"")
				v := line[fq+1 : lq]
				if strings.HasPrefix(v, "/") {
					p := filepath.Join(tmp, filepath.Base(v))
					if os.WriteFile(p, []byte("dummy"), 0o600) != nil {
						t.Fatal(err)
					}
					line = line[:fq+1] + p + line[lq:]
				}
			}
			out.WriteString(line + "\n")
		}
		cp := filepath.Join(tmp, "cfg.json")
		if err := os.WriteFile(cp, []byte(out.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(cp)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s validate: %v", f, err)
		}
	}
}
