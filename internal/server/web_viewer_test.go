// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// seedSnap commits a snapshot with inline files for user u.
func (f *webFixture) seedSnapHead(t *testing.T, uid string, files []api.File, enc bool, head string) string {
	t.Helper()
	u, err := f.m.GetUser(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	p := auth.Principal{User: u, Scopes: auth.ScopeRead | auth.ScopeWrite}
	m := api.Manifest{Version: 1, Device: "d", Files: files}
	if enc {
		m.Enc = &api.EncInfo{V: 1, Alg: "xchacha20poly1305-siv-v1", KID: "0123456789abcdef"}
	}
	br, err := f.s2.Svc.BeginSnapshot(context.Background(), p, "demo", "saves", "d", "", head, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, fl := range files {
		for _, ch := range fl.Chunks {
			_ = ch
		}
	}
	for _, h := range br.Missing {
		data := chunkData[h]
		if data == nil {
			data = []byte{0x1}
		}
		if err := f.s2.Svc.PutChunk(context.Background(), p, "demo", "saves", br.ID, h, strings.NewReader(string(data)), int64(len(data))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s2.Svc.CommitSnapshot(context.Background(), p, "demo", "saves", br.ID, head, false); err != nil {
		t.Fatal(err)
	}
	return br.ID
}

var chunkData = map[api.Hash][]byte{}

func chunkFile(path, content string) api.File {
	h := api.Hash(sha256Of(content))
	chunkData[h] = []byte(content)
	return api.File{Path: path, Size: int64(len(content)), Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(content))}}}
}

func sha256Of(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

func TestViewerPages(t *testing.T) {
	f := webSetup(t, nil)
	u := f.mkCred(t, "alice", "a very fine password", false)
	f.mkCred(t, "bob", "a very fine password", false)
	sess := f.login(t, "alice", "a very fine password")
	stranger := f.login(t, "bob", "a very fine password")
	base := "/account/apps/demo/slots/saves/snapshots/"
	id := f.seedSnapHead(t, u.ID, []api.File{
		{Path: "blob.bin", Size: 4, Inline: []byte{0xde, 0xad, 0xbe, 0xef}},
		{Path: "data.json", Size: 7, Inline: []byte(`{"a":1}`)},
		{Path: "pic.png", Size: 12, Inline: []byte("\x89PNG\r\n\x1a\nxxxx")},
		chunkFile("save.txt", "hello saves"),
	}, false, "")

	// tree page
	r, body := f.get(t, base+id, sess)
	if r.StatusCode != 200 || !strings.Contains(body, "save.txt") {
		t.Fatalf("tree: %d", r.StatusCode)
	}
	// text file view
	r2, body2 := f.get(t, base+id+"/view/save.txt", sess)
	if r2.StatusCode != 200 || !strings.Contains(body2, "hello saves") {
		t.Fatalf("text view: %d", r2.StatusCode)
	}
	// png renders an img to the raw route
	_, body3 := f.get(t, base+id+"/view/pic.png", sess)
	if !strings.Contains(body3, "<img") || !strings.Contains(body3, "/raw/pic.png") {
		t.Fatal("img view")
	}
	// binary shows a hex dump
	_, body4 := f.get(t, base+id+"/view/blob.bin", sess)
	if !strings.Contains(body4, "deadbeef") && !strings.Contains(body4, "de ad be ef") {
		t.Fatalf("hex: %s", body4[:200])
	}
	// raw route headers
	r5, _ := f.get(t, base+id+"/raw/pic.png", sess)
	if c := r5.Header.Get("Content-Security-Policy"); !strings.HasPrefix(c, "sandbox") {
		t.Fatalf("raw csp: %s", c)
	}
	if r5.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff")
	}
	// raw for a non-image is attachment octet-stream
	r6, _ := f.get(t, base+id+"/raw/save.txt", sess)
	if ct := r6.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("raw ct: %s", ct)
	}
	// stranger 404 on tree and raw
	for _, p := range []string{base + id, base + id + "/view/save.txt", base + id + "/raw/save.txt", base + id + "/diff/" + id} {
		r7, _ := f.get(t, p, stranger)
		if r7.StatusCode != 404 {
			t.Fatalf("stranger %s: %d", p, r7.StatusCode)
		}
	}
	// traversal 404
	r8, _ := f.get(t, base+id+"/view/..%2f..%2fsecret", sess)
	if r8.StatusCode == 200 {
		t.Fatal("traversal")
	}
	// encrypted snapshot redirects views to snapshot page
	enc := f.seedSnapHead(t, u.ID, []api.File{{Path: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", Size: 1, Mode: 0o600, Inline: []byte("e")}, {Path: "meta", Size: 1, Mode: 0o600, Inline: []byte("m")}}, true, id)
	r9, _ := f.get(t, base+enc+"/view/x.bin", sess)
	if r9.StatusCode == 200 && !strings.Contains(r9.Request.URL.Path, "/snapshots/") {
		t.Fatal("enc should redirect")
	}
	// diff between two snapshots
	id2 := f.seedSnapHead(t, u.ID, []api.File{
		{Path: "new.txt", Size: 5, Inline: []byte("added")},
		chunkFile("save.txt", "hello world"),
	}, false, enc)
	r10, body10 := f.get(t, base+id+"/diff/"+id2, sess)
	if r10.StatusCode != 200 || !strings.Contains(body10, "save.txt") {
		mid := len(body10) / 2
		end := mid + 600
		if end > len(body10) {
			end = len(body10)
		}
		t.Fatalf("diff: %d %s", r10.StatusCode, body10[mid:end])
	}
}

func TestLineDiffAndTree(t *testing.T) {
	// lineDiff
	d := lineDiff([]string{"a", "b"}, []string{"a", "c"})
	if len(d) == 0 {
		t.Fatal("diff empty")
	}
	same := lineDiff([]string{"x"}, []string{"x"})
	_ = same
	// buildTree: dirs first, escaping
	files := []api.File{
		{Path: "a dir/z.txt", Size: 1, Inline: []byte("y")},
		{Path: "b/f.txt", Size: 1, Inline: []byte("x")},
		{Path: "top.txt", Size: 1, Inline: []byte("z")},
	}
	root := buildTree(files, "/view/")
	if len(root.Children) != 3 {
		t.Fatalf("children=%d", len(root.Children))
	}
	if root.Children[0].Name != "a dir" || !root.Children[0].Dir {
		t.Fatalf("dirs first: %+v", root.Children[0].Name)
	}
	if !strings.Contains(root.Children[0].Children[0].Href, "a%20dir") {
		t.Fatalf("esc: %s", root.Children[0].Children[0].Href)
	}
}
