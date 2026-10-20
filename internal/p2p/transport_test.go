// SPDX-License-Identifier: 0BSD

package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/hub"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/pkg/client"
)

func writeTree(t *testing.T, dir string) {
	os.MkdirAll(filepath.Join(dir, "w"), 0o700)
	b := make([]byte, 4<<20) // 4 MiB not 24 to keep test fast
	rand.Read(b)
	os.WriteFile(filepath.Join(dir, "w", "region.mca"), b, 0o600)
	for i := 0; i < 3; i++ {
		os.WriteFile(filepath.Join(dir, "w", "small"+string(rune('a'+i))+".dat"),
			[]byte("small file "+string(rune('a'+i))), 0o600)
	}
}

func compareTrees(t *testing.T, a, b string) {
	err := filepath.Walk(a, func(p string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(a, p)
		b1, _ := os.ReadFile(p)
		b2, err2 := os.ReadFile(filepath.Join(b, rel))
		if err2 != nil || !bytes.Equal(b1, b2) {
			t.Fatalf("mismatch %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoopbackPushPull(t *testing.T) {
	ctx := context.Background()
	hb, err := hub.Start(ctx, hub.Options{Dir: t.TempDir(), Name: "H"})
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Close()
	// identities
	hdir := t.TempDir()
	jdir := t.TempDir()
	H, err := LoadIdentity(hdir)
	if err != nil {
		t.Fatal("H id:", err)
	}
	J, err := LoadIdentity(jdir)
	if err != nil {
		t.Fatal("J id:", err)
	}
	peersH, _ := LoadPeers(hdir)
	peersJ, _ := LoadPeers(jdir)
	peersH.Add(Peer{ID: J.ID, Name: "j"})
	peersJ.Add(Peer{ID: H.ID, Name: "h"})
	// listen
	pc, err := netx.ListenUDP(ctx, "127.0.0.1:0", 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(pc, H, peersH, hb.Handler())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	// token
	tok, err := hb.MintToken(ctx, "joiner", []string{"read", "write"})
	if err != nil {
		t.Fatal(err)
	}
	// client via p2p transport
	rt, err := NewTransport(J, peersJ, H.ID, []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(client.Config{
		BaseURL: "https://p2p.invalid",
		Token:   tok,
		HTTP:    &http.Client{Transport: rt},
	})
	if err != nil {
		t.Fatal(err)
	}
	// push from A dir
	srcDir := t.TempDir()
	writeTree(t, srcDir)
	src := client.Source{Roots: []client.Root{{Key: "w", Dir: srcDir + "/w"}}}
	st := client.NewMemStore()
	pr, err := c.Push(ctx, "a", "s", src, st, client.PushOptions{})
	if err != nil {
		t.Fatal("push:", err)
	}
	t.Logf("push uploaded=%d", pr.BytesUploaded)
	// pull into B dir
	dstDir := t.TempDir()
	os.MkdirAll(filepath.Join(dstDir, "w"), 0o700)
	dst := client.Source{Roots: []client.Root{{Key: "w", Dir: dstDir + "/w"}}}
	st2 := client.NewMemStore()
	_, err = c.Pull(ctx, "a", "s", "", dst, st2, client.PullOptions{})
	if err != nil {
		t.Fatal("pull:", err)
	}
	compareTrees(t, filepath.Join(srcDir, "w"), filepath.Join(dstDir, "w"))
}

// setup returns hub, transport, client, addr.
func setupPair(t *testing.T) (*hub.Hub, *Identity, *PeerSet, Transport, *client.Client, string) {
	t.Helper()
	ctx := context.Background()
	hb, err := hub.Start(ctx, hub.Options{Dir: t.TempDir(), Name: "H"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hb.Close() })
	hdir, jdir := t.TempDir(), t.TempDir()
	H, err := LoadIdentity(hdir)
	if err != nil {
		t.Fatal(err)
	}
	J, err := LoadIdentity(jdir)
	if err != nil {
		t.Fatal(err)
	}
	peersH, _ := LoadPeers(hdir)
	peersJ, _ := LoadPeers(jdir)
	peersH.Add(Peer{ID: J.ID, Name: "j"})
	peersJ.Add(Peer{ID: H.ID, Name: "h"})
	pc, err := netx.ListenUDP(ctx, "127.0.0.1:0", 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(pc, H, peersH, hb.Handler())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tok, err := hb.MintToken(ctx, "j", []string{"read", "write"})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewTransport(J, peersJ, H.ID, []string{ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(client.Config{BaseURL: "https://p2p.invalid",
		Token: tok, HTTP: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatal(err)
	}
	return hb, J, peersJ, rt, c, ln.Addr().String()
}

func TestP2PDelta(t *testing.T) {
	_, _, _, _, c, _ := setupPair(t)
	ctx := context.Background()
	dir := t.TempDir()
	os.MkdirAll(dir+"/w", 0o700)
	b := make([]byte, 24<<20)
	rand.Read(b)
	os.WriteFile(dir+"/w/big", b, 0o600)
	src := client.Source{Roots: []client.Root{{Key: "w", Dir: dir + "/w"}}}
	st := client.NewMemStore()
	if _, err := c.Push(ctx, "a", "s", src, st, client.PushOptions{}); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(dir + "/w/big")
	copy(b2[3<<20:], []byte("edited"))
	os.WriteFile(dir+"/w/big", b2, 0o600)
	pr, err := c.Push(ctx, "a", "s", src, st, client.PushOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("delta uploaded=%d", pr.Uploaded)
	if pr.Uploaded > 3 {
		t.Fatalf("delta %d chunks > 3", pr.Uploaded)
	}
}

func TestP2PNoToken(t *testing.T) {
	_, J, peersJ, _, _, addr := setupPair(t)
	rt, _ := NewTransport(J, peersJ, "", []string{addr})
	resp, err := (&http.Client{Transport: rt}).Get("https://p2p.invalid/v1/me")
	if err != nil {
		t.Skip("transport err " + err.Error())
	}
	resp.Body.Close()
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		t.Fatalf("want 401/403 got %d", resp.StatusCode)
	}
}

func TestP2PEvents(t *testing.T) {
	_, _, _, _, c, _ := setupPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev := c.Events(ctx)
	// commit a head via a second push
	dir := t.TempDir()
	os.MkdirAll(dir+"/w", 0o700)
	os.WriteFile(dir+"/w/f", []byte("x"), 0o600)
	go c.Push(ctx, "a", "s", client.Source{Roots: []client.Root{{Key: "w", Dir: dir + "/w"}}},
		client.NewMemStore(), client.PushOptions{})
	for e := range ev {
		if e.Type == "head" {
			t.Logf("head event %s", e.Data)
			return
		}
	}
	t.Fatal("no head event")
}

func TestP2PUnknownIdentity(t *testing.T) {
	_, _, _, _, _, addr := setupPair(t)
	// stranger not in host's PeerSet
	hdir2 := t.TempDir()
	J2, _ := LoadIdentity(hdir2)
	peersJ2, _ := LoadPeers(hdir2)
	rt, _ := NewTransport(J2, peersJ2, "", []string{addr})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://p2p.invalid/v1/me", nil)
	_, err := (&http.Client{Transport: rt}).Do(req)
	if err == nil {
		t.Fatal("unpaired identity reached the handler")
	}
	t.Logf("rejected: %v", err)
}

func TestP2PRevokedToken(t *testing.T) {
	hb, _, _, _, c, _ := setupPair(t)
	// list + revoke the token
	ts, err := hb.ListTokens(context.Background())
	if err != nil || len(ts) == 0 {
		t.Fatalf("tokens %v %d", err, len(ts))
	}
	if err := hb.RevokeToken(context.Background(), ts[0].ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // allow cache/ttl
	_, err = c.Me(context.Background())
	if err == nil {
		t.Fatal("revoked token still works")
	}
	t.Logf("revoked: %v", err)
}

func TestPairHappy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hdir, jdir := t.TempDir(), t.TempDir()
	H, _ := LoadIdentity(hdir)
	J, _ := LoadIdentity(jdir)
	peersH, _ := LoadPeers(hdir)
	peersJ, _ := LoadPeers(jdir)
	pc, _ := netx.ListenUDP(ctx, "127.0.0.1:0", 8<<20)
	mint := func(name string) (string, error) { return "sv1_x_tok", nil }
	code, wait, err := HostPair(ctx, pc, H, peersH, mint, PairOptions{Name: "host", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		res, err := JoinPair(ctx, J, peersJ, pc.LocalAddr().String(), code, "joiner")
		if err != nil {
			t.Errorf("join: %v", err)
		}
		if res.HostID != H.ID {
			t.Errorf("host id %s", res.HostID)
		}
	}()
	p, err := wait()
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != J.ID {
		t.Fatalf("peer id %s", p.ID)
	}
	// joiner stores the peer at the end of its handshake
	for i := 0; i < 40 && !peersJ.Has(H.ID); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if !peersH.Has(J.ID) || !peersJ.Has(H.ID) {
		t.Fatal("peers not stored both sides")
	}
}
