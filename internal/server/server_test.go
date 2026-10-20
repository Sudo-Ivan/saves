// SPDX-License-Identifier: 0BSD

package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob/mem"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/Sudo-Ivan/saves/internal/netx/nettest"
	"github.com/Sudo-Ivan/saves/internal/quota"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

type fixture struct {
	srv   *httptest.Server
	s2    *Server
	cli   *http.Client
	m     meta.Store
	b     *mem.Store
	clock *testclock.Clock
	token string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	c := testclock.New(time.Now())
	m, err := sqlite.Open(filepath.Join(t.TempDir(), "m.db"), meta.Options{Clock: c.NowFunc()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := mem.New()
	cfg := config.Defaults()
	cfg.Listen.MinThroughput = config.Size(1 << 10)
	cfg.Quota.AllowUnknownApps = ".*"
	cfg.Log.Access = false
	q := quota.New(&cfg)
	svc := service.New(m, b, q, service.Options{Clock: c.NowFunc(), MaxConcurrentUploadsPerUser: 32})
	chain := auth.Chain{&auth.TokenAuthenticator{Meta: m, Clock: c.NowFunc()}}
	reg := &auth.Registration{Mode: auth.RegOpen, Meta: m, DefaultTier: "free", Clock: c.NowFunc()}
	s := New(svc, m, b, chain, reg, &cfg, Options{Clock: c.NowFunc()})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	t.Cleanup(func() { m.Close() })
	return &fixture{srv: srv, s2: s, m: m, b: b, clock: c, cli: &http.Client{Transport: nettest.LoopbackTransport(false)}}
}

func (f *fixture) tokenFor(t *testing.T, subject string, scopes []string, apps []string) string {
	t.Helper()
	u, _, err := f.m.UpsertUser(context.Background(), subject, "free")
	if err != nil {
		t.Fatal(err)
	}
	id, _, full, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.CreateToken(context.Background(), meta.Token{
		ID: id, UserID: u.ID, SecretHash: hash, Scopes: scopes, Apps: apps, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return full
}

func (f *fixture) do(t *testing.T, method, path string, body io.Reader, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func manifestJSON(files ...api.File) io.Reader {
	m := api.Manifest{Version: 1, Files: files}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(b)
}

func TestFullFlow(t *testing.T) {
	f := setup(t)
	f.token = f.tokenFor(t, "u1", []string{"read", "write"}, nil)
	data := bytes.Repeat([]byte("x"), 200<<10)
	h := api.HashBytes(data)
	hx := hex.EncodeToString(h[:])
	// Begin.
	resp := f.do(t, "POST", "/v1/apps/a/slots/s/snapshots", manifestJSON(api.File{
		Path: "f", Size: int64(len(data)), Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(data))}},
	}), map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != 201 {
		t.Fatalf("begin %d", resp.StatusCode)
	}
	var br struct {
		ID       string   `json:"id"`
		Missing  []string `json:"missing"`
		ChunkURL string   `json:"chunk_url"`
	}
	json.NewDecoder(resp.Body).Decode(&br)
	resp.Body.Close()
	if len(br.Missing) != 1 || br.Missing[0] != hx {
		t.Fatalf("missing %v", br.Missing)
	}
	// PUT chunk.
	req, _ := http.NewRequest("PUT", f.srv.URL+br.ChunkURL+hx, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.ContentLength = int64(len(data))
	resp, err := f.cli.Do(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("put %d %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	// Commit.
	req, _ = http.NewRequest("POST", f.srv.URL+"/v1/apps/a/slots/s/snapshots/"+br.ID+"/commit", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("If-Match", `""`)
	resp, err = f.cli.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("commit %d %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	// Ranged file GET.
	resp = f.do(t, "GET", "/v1/apps/a/slots/s/snapshots/"+br.ID+"/files/f", nil,
		map[string]string{"Range": "bytes=10-19"})
	if resp.StatusCode != 206 {
		t.Fatalf("range %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, data[10:20]) {
		t.Fatal("range content")
	}
	// HEAD.
	resp = f.do(t, "HEAD", "/v1/apps/a/slots/s/snapshots/"+br.ID+"/files/f", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("head %d", resp.StatusCode)
	}
	resp.Body.Close()
	// Chunk GET with range.
	resp = f.do(t, "GET", "/v1/apps/a/chunks/"+hx, nil, map[string]string{"Range": "bytes=0-9"})
	if resp.StatusCode != 206 {
		t.Fatalf("chunk range %d", resp.StatusCode)
	}
	got, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, data[:10]) {
		t.Fatal("chunk range content")
	}
	// Manifest with ETag + gzip.
	resp = f.do(t, "GET", "/v1/apps/a/slots/s/snapshots/"+br.ID, nil,
		map[string]string{"Accept-Encoding": "gzip"})
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("manifest %d enc %q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	gz, _ := gzip.NewReader(resp.Body)
	mbody, _ := io.ReadAll(gz)
	resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no etag")
	}
	resp = f.do(t, "GET", "/v1/apps/a/slots/s/snapshots/"+br.ID, nil,
		map[string]string{"If-None-Match": etag})
	if resp.StatusCode != 304 {
		t.Fatalf("etag %d", resp.StatusCode)
	}
	resp.Body.Close()
	var m api.Manifest
	if err := json.Unmarshal(mbody, &m); err != nil {
		t.Fatal(err)
	}
	// Archive.
	resp = f.do(t, "GET", "/v1/apps/a/slots/s/snapshots/"+br.ID+"/archive.tar", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("archive %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAuthz(t *testing.T) {
	f := setup(t)
	f.token = f.tokenFor(t, "ro", []string{"read"}, nil)
	// Read-only token cannot write.
	resp := f.do(t, "POST", "/v1/apps/a/slots/s/snapshots", manifestJSON(), nil)
	if resp.StatusCode != 403 {
		t.Fatalf("ro write %d", resp.StatusCode)
	}
	resp.Body.Close()
	// No token at all.
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/me", nil)
	resp, err := f.cli.Do(req)
	if err != nil || resp.StatusCode != 401 {
		t.Fatalf("no token %d %v", resp.StatusCode, err)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
	resp.Body.Close()
	// App allowlist.
	f.token = f.tokenFor(t, "lim", []string{"read", "write"}, []string{"ok"})
	resp = f.do(t, "POST", "/v1/apps/other/slots/s/snapshots", manifestJSON(), nil)
	if resp.StatusCode != 403 {
		t.Fatalf("allowlist %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRegister(t *testing.T) {
	f := setup(t)
	resp, err := f.cli.Post(f.srv.URL+"/v1/register", "application/json", strings.NewReader("{}"))
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("register %d %v", resp.StatusCode, err)
	}
	var out struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Token == "" {
		t.Fatal("no token")
	}
	// New token works.
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+out.Token)
	resp, err = f.cli.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("me %d %v", resp.StatusCode, err)
	}
	resp.Body.Close()
}

func TestCrossUserIsolation(t *testing.T) {
	f := setup(t)
	f.token = f.tokenFor(t, "victim", []string{"read", "write"}, nil)
	out := f.do(t, "POST", "/v1/apps/a/slots/s/snapshots", manifestJSON(api.File{
		Path: "f", Size: 4, Chunks: []api.ChunkRef{{Hash: api.HashBytes([]byte("abcd")), Size: 4}},
	}), nil)
	var br struct{ ID string }
	json.NewDecoder(out.Body).Decode(&br)
	out.Body.Close()
	// Attacker cannot read.
	f.token = f.tokenFor(t, "attacker", []string{"read", "write"}, nil)
	resp := f.do(t, "GET", "/v1/apps/a/slots/s", nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("slot leak %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = f.do(t, "GET", "/v1/apps/a/slots/s/snapshots/"+br.ID, nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("manifest leak %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func FuzzRoutePaths(f *testing.F) {
	f.Add("GET", "/v1/me", "x=1")
	f.Add("POST", "/v1/apps/../slots/s", "")
	fix := setup(&testing.T{})
	defer fix.srv.Close()
	f.Fuzz(func(t *testing.T, method, path, q string) {
		if strings.ContainsAny(path, " \t\n") || !strings.HasPrefix(path, "/") {
			return
		}
		req, err := http.NewRequest(method, fix.srv.URL+path+"?"+q, nil)
		if err != nil {
			return
		}
		resp, err := fix.cli.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("5xx on %s %s", method, path)
		}
	})
}

func FuzzProblemEncode(f *testing.F) {
	f.Add("conflict", "x", 409)
	f.Fuzz(func(t *testing.T, code, title string, status int) {
		p := &api.Problem{Code: code, Title: title, Status: status}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var back api.Problem
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzAuthHeader(f *testing.F) {
	f.Add("Bearer sv1_0123456789abcdef_")
	f.Fuzz(func(t *testing.T, hdr string) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = "1.2.3.4:5"
		if hdr != "" {
			r.Header.Set("Authorization", hdr)
		}
		_ = r.Header.Get("Authorization")
	})
}

func FuzzParseRange(f *testing.F) {
	f.Add("bytes=0-99")
	f.Add("bytes=-50")
	f.Add("bytes=0-,0-")
	f.Add("items=1-2")
	f.Add("bytes=abc-def")
	f.Add("bytes=0-99999999999999999999")
	fix := setup(&testing.T{})
	defer fix.srv.Close()
	fix.token = fix.tokenFor(nil2t(f), "rfz", []string{"read", "write"}, nil)
	data := bytes.Repeat([]byte("R"), 4096)
	h := api.HashBytes(data)
	resp := fix.do(&testing.T{}, "POST", "/v1/apps/a/slots/s/snapshots", manifestJSON(api.File{
		Path: "f", Size: int64(len(data)), Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(data))}}}), nil)
	var br struct {
		ID       string `json:"id"`
		ChunkURL string `json:"chunk_url"`
	}
	json.NewDecoder(resp.Body).Decode(&br)
	resp.Body.Close()
	put, _ := http.NewRequest("PUT", fix.srv.URL+br.ChunkURL+hex.EncodeToString(h[:]), bytes.NewReader(data))
	put.Header.Set("Authorization", "Bearer "+fix.token)
	put.ContentLength = int64(len(data))
	if r, err := fix.cli.Do(put); err == nil {
		r.Body.Close()
	}
	cm, _ := http.NewRequest("POST", fix.srv.URL+"/v1/apps/a/slots/s/snapshots/"+br.ID+"/commit", nil)
	cm.Header.Set("Authorization", "Bearer "+fix.token)
	cm.Header.Set("If-Match", `""`)
	if r, err := fix.cli.Do(cm); err == nil {
		r.Body.Close()
	}
	url := fix.srv.URL + "/v1/apps/a/slots/s/snapshots/" + br.ID + "/files/f"
	f.Fuzz(func(t *testing.T, rangeHdr string) {
		if strings.ContainsAny(rangeHdr, "\r\n") {
			return
		}
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+fix.token)
		req.Header.Set("Range", rangeHdr)
		resp, err := fix.cli.Do(req)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(len(data))*4+64<<10))
		resp.Body.Close()
		switch resp.StatusCode {
		case 200, 206, 416, 400, 401, 429:
		default:
			t.Fatalf("bad status %d for %q", resp.StatusCode, rangeHdr)
		}
		if resp.StatusCode == 200 && len(body) > len(data) {
			t.Fatalf("oversize body %d", len(body))
		}
		if resp.StatusCode == 206 && !strings.HasPrefix(resp.Header.Get("Content-Type"), "multipart/") {
			cr := resp.Header.Get("Content-Range")
			if cr == "" {
				t.Fatal("206 without Content-Range")
			}
		}
	})
}

// nil2t adapts *testing.F helpers that need a *testing.T; unused at runtime.
func nil2t(f *testing.F) *testing.T { return &testing.T{} }
