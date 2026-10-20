// SPDX-License-Identifier: 0BSD

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"512MiB": 512 << 20, "10GB": 10e9, "1KiB": 1 << 10,
		"100": 100, "0": 0, "2TiB": 2 << 40, "1.5GiB": 1<<30 + 512<<20,
		"5 mb": 5e6, "512mib": 512 << 20,
	}
	for in, want := range cases {
		got, err := ParseSize(in)
		if err != nil {
			t.Errorf("ParseSize(%q): %v", in, err)
			continue
		}
		if got.Int64() != want {
			t.Errorf("ParseSize(%q) = %d, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "10XB", "abc", "1e30"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"30s": 30 * time.Second, "5m": 5 * time.Minute, "24h": 24 * time.Hour,
		"90d": 90 * 24 * time.Hour, "10": 10 * time.Second, "1.5h": 90 * time.Minute,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil {
			t.Errorf("ParseDuration(%q): %v", in, err)
			continue
		}
		if got.Duration() != want {
			t.Errorf("ParseDuration(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"", "x", "10w"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted", bad)
		}
	}
}

func TestDefaultsValidate(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saves.json")
	if err := os.WriteFile(path, []byte(`{"listen":{"addr":":8443"},"bogus":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown key accepted")
	}
	if err := os.WriteFile(path, []byte(`{"listen":{"addr":":8443"},"log":{"level":"debug"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.Addr != ":8443" || c.Log.Level != "debug" {
		t.Fatal("decode mismatch")
	}
}

func TestEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saves.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAVES_LISTEN_ADDR", ":9443")
	t.Setenv("SAVES_LOG_LEVEL", "warn")
	t.Setenv("SAVES_GC_INTERVAL", "90s")
	t.Setenv("SAVES_LIMITS_MAX_CHUNK_BYTES", "4MiB")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.Addr != ":9443" || c.Log.Level != "warn" {
		t.Fatal("env override not applied")
	}
	if c.GC.Interval.Duration() != 90*time.Second {
		t.Fatal("duration env override not applied")
	}
	if c.Limits.MaxChunkBytes.Int64() != 4<<20 {
		t.Fatal("size env override not applied")
	}
}

func TestSecretFile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "dsn")
	if err := os.WriteFile(secret, []byte("postgres://u:p@h/db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "saves.json")
	doc := `{"storage":{"meta":{"driver":"postgres","postgres":{"dsn_file":"` + secret + `"}}}}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.Meta.Postgres.DSN != "postgres://u:p@h/db" {
		t.Fatalf("dsn %q", c.Storage.Meta.Postgres.DSN)
	}
}

func TestRedacted(t *testing.T) {
	c := Defaults()
	c.Auth.IPSecret = "topsecret"
	c.Registration.InviteCodes = []string{"code1", "code2"}
	r := c.Redacted()
	if r.Auth.IPSecret != "[redacted]" || r.Registration.InviteCodes[0] != "[redacted]" {
		t.Fatal("secrets not redacted")
	}
	if c.Auth.IPSecret != "topsecret" {
		t.Fatal("redact mutated source")
	}
}

func TestModeWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saves.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := ModeWarning(path); w == "" {
		t.Fatal("no warning for 0644 config")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if w := ModeWarning(path); w != "" {
		t.Fatalf("unexpected warning %q", w)
	}
}

func TestDiffReloadable(t *testing.T) {
	a := Defaults()
	b := Defaults()
	b.Log.Level = "debug"
	if got := DiffReloadable(a, b); len(got) != 1 || got[0] != "log" {
		t.Fatalf("DiffReloadable = %v", got)
	}
	b.Listen.Addr = ":1"
	if got := Diff(a, b); len(got) != 2 {
		t.Fatalf("Diff = %v", got)
	}
}

func TestDocUpToDate(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "config.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("docs/config.md missing, run make docs: %v", err)
	}
	if string(data) != RenderDoc() {
		t.Fatal("docs/config.md is stale, run make docs")
	}
}

func FuzzParseSize(f *testing.F) {
	f.Add("512MiB")
	f.Add("10")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseSize(s)
	})
}

func FuzzParseDuration(f *testing.F) {
	f.Add("30s")
	f.Add("90d")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseDuration(s)
	})
}

func FuzzConfigDecode(f *testing.F) {
	f.Add(`{"listen":{"addr":":8443"}}`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeConfig(strings.NewReader(s))
	})
}
