// SPDX-License-Identifier: 0BSD

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/clicfg"
	"github.com/Sudo-Ivan/saves/internal/testserver"
	"github.com/Sudo-Ivan/saves/pkg/client"
)

func testEnv(t *testing.T) *Env {
	t.Helper()
	p := clicfg.Paths{
		Config: t.TempDir(), State: t.TempDir(), Cache: t.TempDir(),
	}
	return &Env{
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{}, Getenv: func(string) string { return "" },
		Paths: p,
	}
}

func TestCompletionDrift(t *testing.T) {
	e := testEnv(t)
	if code := Main(context.Background(), e, []string{"completion", "bash"}); code != 0 {
		t.Fatalf("completion exit %d", code)
	}
	out := e.Stdout.(*bytes.Buffer).String()
	for _, n := range Commands() {
		if !strings.Contains(out, n) {
			t.Fatalf("completion missing %q", n)
		}
	}
}

func TestUsageExitCode(t *testing.T) {
	e := testEnv(t)
	if code := Main(context.Background(), e, []string{"nope"}); code != ExUsage {
		t.Fatalf("want usage got %d", code)
	}
	if code := Main(context.Background(), e, []string{"me"}); code == ExOK {
		t.Fatal("me without config should fail")
	}
}

func TestConfigRoundTrip(t *testing.T) {
	e := testEnv(t)
	p := e.Paths
	cfg, err := clicfg.Load(p, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server = "http://x"
	cfg.Token = "secret"
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := clicfg.Load(p, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if got.Server != "http://x" || got.Token != "secret" {
		t.Fatal("roundtrip")
	}
	if got.Redacted().Token != "(set)" {
		t.Fatal("redaction")
	}
}

func TestGameRef(t *testing.T) {
	a, s, err := clicfg.GameRef("minecraft-java/W1")
	if err != nil || a != "minecraft-java" || s != "W1" {
		t.Fatalf("%s %s %v", a, s, err)
	}
	a, s, err = clicfg.GameRef("app")
	if err != nil || a != "app" || s != "default" {
		t.Fatalf("%s %s %v", a, s, err)
	}
}

func TestMeWithServer(t *testing.T) {
	ts := testserver.New(t)
	tok := ts.Token(t, "u", []string{"read", "write"}, nil)
	e := testEnv(t)
	e.Client = func(cfg clicfg.Config) (*client.Client, error) {
		return client.New(client.Config{BaseURL: ts.Srv.URL, Token: tok,
			HTTP: ts.Srv.Client()})
	}
	if code := Main(context.Background(), e, []string{"me", "--server", ts.Srv.URL, "--token", tok}); code != 0 {
		t.Fatalf("me exit %d: %s", code, e.Stderr.(*bytes.Buffer).String())
	}
	if !strings.Contains(e.Stdout.(*bytes.Buffer).String(), "tier:") {
		t.Fatalf("out: %s", e.Stdout)
	}
}

func FuzzParseGameRef(f *testing.F) {
	f.Add("a/b")
	f.Add("a")
	f.Add("/x")
	f.Add("a/b/c")
	f.Fuzz(func(t *testing.T, s string) {
		a, sl, err := clicfg.GameRef(s)
		if err == nil {
			if a == "" || sl == "" {
				t.Fatalf("empty %q -> %q %q", s, a, sl)
			}
		}
	})
}
