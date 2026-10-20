// SPDX-License-Identifier: 0BSD

package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/netx/nettest"
	"github.com/Sudo-Ivan/saves/internal/testserver"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

func benchTree(b *testing.B, n int) string {
	d := b.TempDir()
	for i := 0; i < n; i++ {
		p := filepath.Join(d, fmt.Sprintf("dir%d", i%50), fmt.Sprintf("f%d.sav", i))
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(fmt.Sprintf("data-%d", i)), 0o600)
	}
	return d
}

func BenchmarkPushPull10k(b *testing.B) {
	c, _ := setup2(b)
	ctx := context.Background()
	src := Source{Roots: []Root{{Key: "save", Dir: benchTree(b, 10000)}}}
	st := NewMemStore()
	b.ResetTimer()
	pr, err := c.Push(ctx, "a", "s", src, st, PushOptions{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(pr.Files), "files")
	dst := Source{Roots: []Root{{Key: "save", Dir: b.TempDir()}}}
	_, err = c.Pull(ctx, "a", "s", "", dst, NewMemStore(), PullOptions{})
	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkPush1GiB(b *testing.B) {
	c, _ := setup2(b)
	ctx := context.Background()
	d := b.TempDir()
	f := filepath.Join(d, "big")
	const n = 256 << 20 // reduced from 1GiB for bench time
	buf := make([]byte, 16<<20)
	if _, err := rand.Read(buf); err != nil {
		b.Fatal(err)
	}
	fp, _ := os.Create(f)
	for i := 0; i < n/len(buf); i++ {
		fp.Write(buf)
	}
	fp.Close()
	src := Source{Roots: []Root{{Key: "save", Dir: d}}}
	st := NewMemStore()
	b.ResetTimer()
	pr, err := c.Push(ctx, "a", "s", src, st, PushOptions{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(n)/pr.Duration.Seconds()/(1<<20), "MB/s-cold")
	// warm: second push unchanged path
	pr2, _ := c.Push(ctx, "a", "s", src, st, PushOptions{})
	b.ReportMetric(float64(n)/pr2.Duration.Seconds()/(1<<20), "MB/s-warm")
}

func BenchmarkPlan10k(b *testing.B) {
	c, _ := setup2(b)
	ctx := context.Background()
	src := Source{Roots: []Root{{Key: "save", Dir: benchTree(b, 10000)}}}
	st := NewMemStore()
	if _, err := c.Push(ctx, "a", "s", src, st, PushOptions{}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Plan(ctx, "a", "s", src, st); err != nil {
			b.Fatal(err)
		}
	}
}

func setup2(t testing.TB) (*Client, *testserver.T) {
	ts := testserver.New(t)
	tok := ts.Token(t, "u", []string{"read", "write"}, nil)
	c, err := New(Config{BaseURL: ts.Srv.URL, Token: tok,
		HTTP: &http.Client{Transport: nettest.LoopbackTransport(false)}})
	if err != nil {
		t.Fatal(err)
	}
	return c, ts
}

var _ = api.Hash{}
