package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
)

func tokStore(t *testing.T) meta.Store {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "m.db"), meta.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestAdminToken(t *testing.T) {
	st := tokStore(t)
	cf := config.Defaults()
	cf.Auth.Token.AuditEnabled = true
	ctx := context.Background()
	u, _, _ := st.UpsertUser(ctx, "cli-sub", "free")
	_ = u

	// create with flags
	old := os.Stdout
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	os.Stdout = pw
	rc := adminToken(ctx, &cf, st, []string{"create", "cli-sub",
		"-name", "x", "-expires", "30d", "-cidr", "10.0.0.0/8,203.0.113.7",
		"-scopes", "read", "-app", "demo"})
	pw.Close()
	os.Stdout = old
	if rc != 0 {
		t.Fatalf("create: %d", rc)
	}
	ts, _ := st.ListTokens(ctx, u.ID)
	if len(ts) != 1 {
		t.Fatal("no token")
	}
	tk := ts[0]
	if tk.ExpiresAt == nil || len(tk.AllowedCIDRs) != 2 || tk.Apps[0] != "demo" || tk.Name != "x" {
		t.Fatalf("stored: %+v", tk)
	}
	// show prints stats
	r2, w2, _ := os.Pipe()
	os.Stdout = w2
	rc = adminToken(ctx, &cf, st, []string{"show", tk.ID})
	w2.Close()
	os.Stdout = old
	if rc != 0 {
		t.Fatalf("show: %d", rc)
	}
	buf := make([]byte, 8192)
	n, _ := r2.Read(buf)
	r2.Close()
	out := string(buf[:n])
	if out == "" || !strings.Contains(out, "requests: total=") {
		t.Fatalf("show: %q", out)
	}
	// events kind filter
	rc = adminToken(ctx, &cf, st, []string{"events", tk.ID, "-kind", "created", "-n", "5"})
	if rc != 0 {
		t.Fatalf("events: %d", rc)
	}
	// set name writes renamed event
	rc = adminToken(ctx, &cf, st, []string{"set", tk.ID, "-name", "y"})
	if rc != 0 {
		t.Fatalf("set: %d", rc)
	}
	ev, _, _ := st.ListTokenEvents(ctx, tk.ID, "renamed", "", 10)
	if len(ev) == 0 {
		t.Fatal("no renamed event")
	}
	// invalid cidr exits 2, no token
	rc = adminToken(ctx, &cf, st, []string{"create", "cli-sub", "-name", "bad", "-cidr", "junk"})
	if rc != 2 {
		t.Fatalf("bad cidr: %d", rc)
	}
	// positional form still works
	rc = adminToken(ctx, &cf, st, []string{"create", "cli-sub", "posname"})
	if rc != 0 {
		t.Fatalf("positional: %d", rc)
	}
	// revoke writes revoked event
	rc = adminToken(ctx, &cf, st, []string{"revoke", tk.ID})
	if rc != 0 {
		t.Fatalf("revoke: %d", rc)
	}
	ev, _, _ = st.ListTokenEvents(ctx, tk.ID, "revoked", "", 10)
	if len(ev) == 0 {
		t.Fatal("no revoked event")
	}
}
