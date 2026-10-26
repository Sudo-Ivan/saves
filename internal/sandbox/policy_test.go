// SPDX-License-Identifier: 0BSD

package sandbox

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/config"
)

var update = flag.Bool("update", false, "write golden")

func golden(t *testing.T, name string, cfg *config.Config, want func(*Policy)) {
	p, err := FromConfig(cfg, "/etc/saves/config.json")
	if err != nil {
		t.Fatal(err)
	}
	if want != nil {
		want(p)
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	f := filepath.Join("testdata", name+".golden")
	if *update {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(f, b, 0o644)
		return
	}
	w, err := os.ReadFile(f)
	if err != nil {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, b, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("wrote new golden %s", f)
	}
	if string(w) != string(b) {
		t.Fatalf("policy drift:\n%s", b)
	}
}

func TestPolicyGolden(t *testing.T) {
	small := config.Defaults()
	small.Storage.Blob.FS.Root = "/data/blobs"
	small.Storage.Meta.SQLite.Path = "/data/meta.db"
	golden(t, "small", &small, func(p *Policy) {
		found := false
		for _, d := range p.RWDirs {
			if d == "/data/blobs" {
				found = true
			}
		}
		if !found {
			t.Fatal("blob root not rw")
		}
	})
}

func FuzzPolicyFromConfig(f *testing.F) {
	f.Add("/a", "/b", "x")
	f.Fuzz(func(t *testing.T, blob, meta, extra string) {
		cfg := config.Defaults()
		cfgP := &cfg
		cfg.Storage.Blob.FS.Root = blob
		cfg.Storage.Meta.SQLite.Path = meta
		cfg.Sandbox.ExtraRWPaths = []string{extra}
		p, err := FromConfig(cfgP, "/c")
		if err != nil {
			return
		}
		for _, d := range p.RWDirs {
			if d == "" || d == "/" {
				t.Fatalf("bad rw %q", d)
			}
			if !filepath.IsAbs(d) && !strings.HasPrefix(d, "/") {
				t.Fatalf("relative rw %q", d)
			}
		}
	})
}

// TestPolicyWebOIDCPort covers the web OIDC issuer connect port.
func TestPolicyWebOIDCPort(t *testing.T) {
	cfg := config.Defaults()
	cfg.Web.Enabled = true
	cfg.Web.Secret = "0123456789abcdef0123456789abcdef"
	cfg.Web.OIDC.Enabled = true
	cfg.Web.OIDC.Issuer = "https://idp.example.com:8443"
	cfg.Web.OIDC.ClientID = "saves"
	cfg.Web.PublicURL = "https://saves.example.com"
	p, err := FromConfig(&cfg, "/etc/saves/config.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range p.ConnectTCP {
		if port == 8443 {
			return
		}
	}
	t.Fatalf("connect tcp %v lacks 8443", p.ConnectTCP)
}
