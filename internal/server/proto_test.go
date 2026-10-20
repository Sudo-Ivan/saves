// SPDX-License-Identifier: 0BSD

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/blob/mem"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/netx/nettest"
	"github.com/Sudo-Ivan/saves/internal/quota"
	"github.com/Sudo-Ivan/saves/internal/ratelimit"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/Sudo-Ivan/saves/pkg/api"
	"github.com/quic-go/quic-go/http3"
)

func selfSigned(t *testing.T, dir string) (cert, key string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	cert = filepath.Join(dir, "cert.pem")
	key = filepath.Join(dir, "key.pem")
	writePEM(t, cert, "CERTIFICATE", der)
	ek, _ := x509.MarshalECPrivateKey(priv)
	writePEM(t, key, "EC PRIVATE KEY", ek)
	return cert, key
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func insecureClient(t *testing.T, h2 bool) *http.Client {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- test client
	if h2 {
		tr.ForceAttemptHTTP2 = true
	} else {
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	tr.DialContext = netx.Dialer().DialContext
	return &http.Client{Transport: tr}
}

func TestProtocols(t *testing.T) {
	f := setup(t)
	f.srv.Close()
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	f.clock = testclock.New(time.Now())
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	cfg.Listen.TLS = config.TLSConfig{Mode: "files", CertFile: cert, KeyFile: key, MinVersion: "1.2"}
	cfg.Listen.Addr = "127.0.0.1:0"
	cfg.Listen.Protocols = []string{"h1", "h2"}
	q := quota.New(&cfg)
	svc := service.New(f.m, f.b, q, service.Options{Clock: f.clock.NowFunc()})
	s := New(svc, f.m, f.b, auth.Chain{&auth.TokenAuthenticator{Meta: f.m}}, nil, &cfg, Options{Clock: f.clock.NowFunc()})
	r := NewRunner(s, &cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.loadTLS(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	go r.Serve(ctx)
	addr := r.lnTCP.Addr().String()
	f.token = f.tokenFor(t, "p", []string{"read"}, nil)

	// HTTP/1.1 over TLS.
	resp, err := insecureClient(t, false).Get("https://" + addr + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("h1 expected, got %d", resp.ProtoMajor)
	}
	resp.Body.Close()
	// HTTP/2 over TLS.
	resp, err = insecureClient(t, true).Get("https://" + addr + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("h2 expected, got %d", resp.ProtoMajor)
	}
	resp.Body.Close()
}

func TestH2C(t *testing.T) {
	f := setup(t)
	f.srv.Close()
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	cfg.Listen.Addr = "127.0.0.1:0"
	cfg.Listen.Protocols = []string{"h2c"}
	cfg.Listen.TLS.Mode = "none"
	q := quota.New(&cfg)
	svc := service.New(f.m, f.b, q, service.Options{Clock: f.clock.NowFunc()})
	s := New(svc, f.m, f.b, auth.Chain{&auth.TokenAuthenticator{Meta: f.m}}, nil, &cfg, Options{Clock: f.clock.NowFunc()})
	r := NewRunner(s, &cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.loadTLS(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	go r.Serve(ctx)
	addr := r.lnTCP.Addr().String()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	protos := new(http.Protocols)
	protos.SetUnencryptedHTTP2(true)
	tr.Protocols = protos
	tr.DialContext = netx.Dialer().DialContext
	cl := &http.Client{Transport: tr}
	resp, err := cl.Get("http://" + addr + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("h2c expected proto 2, got %d", resp.ProtoMajor)
	}
	resp.Body.Close()
}

func TestCertHotReload(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	cfg := config.Defaults()
	cfg.Listen.TLS = config.TLSConfig{Mode: "files", CertFile: cert, KeyFile: key}
	f := setup(t)
	f.srv.Close()
	q := quota.New(&cfg)
	svc := service.New(f.m, f.b, q, service.Options{Clock: f.clock.NowFunc()})
	s := New(svc, f.m, f.b, auth.Chain{}, nil, &cfg, Options{Clock: f.clock.NowFunc()})
	r := NewRunner(s, &cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.loadTLS(ctx); err != nil {
		t.Fatal(err)
	}
	// Rewrite cert and reload.
	cert2, key2 := selfSigned(t, dir)
	_ = cert2
	_ = key2
	if err := r.ReloadCert(); err != nil {
		t.Fatal(err)
	}
}

func setupT(t testing.TB) *fixture { return setup2(t) }

func setup2(t testing.TB) *fixture {
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
	cfg.Quota.AllowUnknownApps = ".*"
	q := quota.New(&cfg)
	svc := service.New(m, b, q, service.Options{Clock: c.NowFunc(), MaxConcurrentUploadsPerUser: 32})
	s := New(svc, m, b, auth.Chain{&auth.TokenAuthenticator{Meta: m, Clock: c.NowFunc()}}, nil, &cfg, Options{Clock: c.NowFunc(), LimiterIP: ratelimit.New(1e9, 1e9, 1<<16, c.NowFunc())})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	t.Cleanup(func() { m.Close() })
	return &fixture{srv: srv, m: m, b: b, clock: c, cli: &http.Client{Transport: nettest.LoopbackTransport(false)}}
}

func (f *fixture) tokenForB(t testing.TB, subject string, scopes, apps []string) string {
	u, _, _ := f.m.UpsertUser(context.Background(), subject, "free")
	id, _, full, hash, _ := auth.GenerateToken()
	f.m.CreateToken(context.Background(), meta.Token{ID: id, UserID: u.ID, SecretHash: hash, Scopes: scopes, Apps: apps})
	return full
}

func (f *fixture) doB(t testing.TB, method, path string, body io.Reader, hdr map[string]string) *http.Response {
	req, _ := http.NewRequest(method, f.srv.URL+path, body)
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

func BenchmarkChunkPUT(b *testing.B) {
	f := setupT(b)
	defer f.srv.Close()
	f.token = f.tokenForB(b, "u", []string{"read", "write"}, nil)
	data := bytes.Repeat([]byte{9}, 1<<20)
	h := api.HashBytes(data)
	hx := hex.EncodeToString(h[:])
	resp := f.doB(b, "POST", "/v1/apps/a/slots/s/snapshots", manifestJSON(api.File{
		Path: "f", Size: int64(len(data)), Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(data))}},
	}), nil)
	var br struct {
		ID       string `json:"id"`
		ChunkURL string `json:"chunk_url"`
	}
	json.NewDecoder(resp.Body).Decode(&br)
	resp.Body.Close()
	url := f.srv.URL + br.ChunkURL + hx
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+f.token)
		req.ContentLength = int64(len(data))
		resp, err := f.cli.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func TestH3(t *testing.T) {
	f := setup(t)
	f.srv.Close()
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	cfg.Listen.TLS = config.TLSConfig{Mode: "files", CertFile: cert, KeyFile: key}
	cfg.Listen.Addr = "127.0.0.1:0"
	cfg.Listen.H3Addr = "127.0.0.1:0"
	cfg.Listen.Protocols = []string{"h1", "h2", "h3"}
	cfg.Listen.AltSvc = `h3=":443"; ma=86400`
	q := quota.New(&cfg)
	svc := service.New(f.m, f.b, q, service.Options{Clock: f.clock.NowFunc(), MaxConcurrentUploadsPerUser: 32})
	ta := &auth.TokenAuthenticator{Meta: f.m}
	s := New(svc, f.m, f.b, auth.Chain{ta}, nil, &cfg,
		Options{Clock: f.clock.NowFunc(), LimiterIP: ratelimit.New(1e9, 1e9, 1<<16, f.clock.NowFunc())})
	svc.TokenInvalidator = ta.Invalidate
	r := NewRunner(s, &cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.loadTLS(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	go r.Serve(ctx)
	addr := r.lnTCP.Addr().String()
	f.token = f.tokenFor(t, "h3user", []string{"read", "write"}, nil)

	// Alt-Svc on TCP response.
	resp, err := insecureClient(t, true).Get("https://" + addr + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("missing Alt-Svc")
	}
	resp.Body.Close()

	// h3 round trip against the real UDP addr.
	h3c := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- test
	defer h3c.Close()
	cl := &http.Client{Transport: h3c}
	h3addr := r.H3Addr()
	resp, err = cl.Get("https://" + h3addr + "/v1/me")
	if err != nil {
		t.Fatalf("h3 get: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("h3 expected proto 3, got %d", resp.ProtoMajor)
	}
	resp.Body.Close()

	// Full flow over h3: begin, 16 parallel PUTs, commit, ranged GET.
	data := bytes.Repeat([]byte{7}, 300<<10)
	h := api.HashBytes(data)
	hx := hex.EncodeToString(h[:])
	m := manifestJSON(api.File{Path: "f", Size: int64(len(data)),
		Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(data))}}})
	resp = func() *http.Response {
		req, _ := http.NewRequest("POST", "https://"+h3addr+"/v1/apps/a/slots/s/snapshots", m)
		req.Header.Set("Authorization", "Bearer "+f.token)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}()
	var br struct {
		ID       string `json:"id"`
		ChunkURL string `json:"chunk_url"`
	}
	json.NewDecoder(resp.Body).Decode(&br)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("h3 begin %d", resp.StatusCode)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("PUT", "https://"+h3addr+br.ChunkURL+hx, bytes.NewReader(data))
			req.Header.Set("Authorization", "Bearer "+f.token)
			req.ContentLength = int64(len(data))
			resp, err := cl.Do(req)
			if err != nil {
				errs <- err
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	req, _ := http.NewRequest("POST", "https://"+h3addr+"/v1/apps/a/slots/s/snapshots/"+br.ID+"/commit", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("If-Match", `""`)
	resp, err = cl.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("h3 commit %d %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	// Ranged GET over h3.
	req, _ = http.NewRequest("GET", "https://"+h3addr+"/v1/apps/a/slots/s/snapshots/"+br.ID+"/files/f", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Range", "bytes=100-199")
	resp, err = cl.Do(req)
	if err != nil || resp.StatusCode != 206 {
		t.Fatalf("h3 range %d %v", resp.StatusCode, err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, data[100:200]) {
		t.Fatal("h3 range content")
	}
}

func TestNoAltSvcWhenDisabled(t *testing.T) {
	f := setup(t)
	f.token = f.tokenFor(t, "u", []string{"read"}, nil)
	resp := f.do(t, "GET", "/v1/me", nil, nil)
	if resp.Header.Get("Alt-Svc") != "" {
		t.Fatal("unexpected Alt-Svc")
	}
	resp.Body.Close()
}

func TestRange(t *testing.T) {
	f := setup(t)
	f.token = f.tokenFor(t, "r", []string{"read", "write"}, nil)
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 251)
	}
	h := api.HashBytes(data)
	m := manifestJSON(api.File{Path: "f", Size: int64(len(data)),
		Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(data))}}})
	resp := f.do(t, "POST", "/v1/apps/a/slots/s/snapshots", m, nil)
	var br struct {
		ID       string `json:"id"`
		ChunkURL string `json:"chunk_url"`
	}
	json.NewDecoder(resp.Body).Decode(&br)
	resp.Body.Close()
	put, _ := http.NewRequest("PUT", f.srv.URL+br.ChunkURL+hex.EncodeToString(h[:]), bytes.NewReader(data))
	put.Header.Set("Authorization", "Bearer "+f.token)
	put.ContentLength = int64(len(data))
	pr, _ := f.cli.Do(put)
	if pr != nil {
		pr.Body.Close()
	}
	c, _ := http.NewRequest("POST", f.srv.URL+"/v1/apps/a/slots/s/snapshots/"+br.ID+"/commit", nil)
	c.Header.Set("Authorization", "Bearer "+f.token)
	c.Header.Set("If-Match", `""`)
	cr, _ := f.cli.Do(c)
	if cr != nil {
		cr.Body.Close()
	}

	get := func(hdr map[string]string, method string) *http.Response {
		return f.do(t, method, "/v1/apps/a/slots/s/snapshots/"+br.ID+"/files/f", nil, hdr)
	}
	// single
	r1 := get(map[string]string{"Range": "bytes=0-99"}, "GET")
	if r1.StatusCode != 206 {
		t.Fatalf("single %d", r1.StatusCode)
	}
	g, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	if !bytes.Equal(g, data[:100]) {
		t.Fatal("single range")
	}
	// suffix
	r2 := get(map[string]string{"Range": "bytes=-50"}, "GET")
	g, _ = io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != 206 || !bytes.Equal(g, data[950:]) {
		t.Fatalf("suffix %d", r2.StatusCode)
	}
	// open-ended
	r3 := get(map[string]string{"Range": "bytes=900-"}, "GET")
	g, _ = io.ReadAll(r3.Body)
	r3.Body.Close()
	if r3.StatusCode != 206 || !bytes.Equal(g, data[900:]) {
		t.Fatalf("open %d", r3.StatusCode)
	}
	// multi
	r4 := get(map[string]string{"Range": "bytes=0-9,500-509"}, "GET")
	g, _ = io.ReadAll(r4.Body)
	ct := r4.Header.Get("Content-Type")
	r4.Body.Close()
	if r4.StatusCode != 206 || !strings.HasPrefix(ct, "multipart/byteranges") {
		t.Fatalf("multi %d %s", r4.StatusCode, ct)
	}
	if len(g) > 4096 {
		t.Fatalf("multi body too big %d", len(g))
	}
	// unsatisfiable
	r5 := get(map[string]string{"Range": "bytes=2000-"}, "GET")
	r5.Body.Close()
	if r5.StatusCode != 416 {
		t.Fatalf("unsat %d", r5.StatusCode)
	}
	// too many ranges
	many := "bytes=" + strings.Repeat("0-,", 30) + "0-0"
	r6 := get(map[string]string{"Range": many}, "GET")
	r6.Body.Close()
	if r6.StatusCode != 416 {
		t.Fatalf("too many ranges %d", r6.StatusCode)
	}
	// If-Range etag match/mismatch
	hdr, _ := http.NewRequest("GET", f.srv.URL+"/v1/apps/a/slots/s/snapshots/"+br.ID+"/files/f", nil)
	hdr.Header.Set("Authorization", "Bearer "+f.token)
	etagResp, _ := f.cli.Do(hdr)
	etag := etagResp.Header.Get("ETag")
	etagResp.Body.Close()
	r7 := get(map[string]string{"Range": "bytes=0-9", "If-Range": etag}, "GET")
	r7.Body.Close()
	if r7.StatusCode != 206 {
		t.Fatalf("if-range match %d", r7.StatusCode)
	}
	r8 := get(map[string]string{"Range": "bytes=0-9", "If-Range": `"nope"`}, "GET")
	r8.Body.Close()
	if r8.StatusCode != 200 {
		t.Fatalf("if-range mismatch %d", r8.StatusCode)
	}
	// Range + HEAD
	r9 := get(map[string]string{"Range": "bytes=0-9"}, "HEAD")
	r9.Body.Close()
	if r9.StatusCode != 206 {
		t.Fatalf("head range %d", r9.StatusCode)
	}
}

func TestReadyzDraining(t *testing.T) {
	f := setup(t)
	// flip drain flag directly
	f.srv.Close()
	cfg := config.Defaults()
	cfg.Quota.AllowUnknownApps = ".*"
	cfg.Listen.Addr = "127.0.0.1:0"
	cfg.Listen.TLS.Mode = "none"
	cfg.Listen.Protocols = []string{"h1"}
	q := quota.New(&cfg)
	svc := service.New(f.m, f.b, q, service.Options{Clock: f.clock.NowFunc()})
	s := New(svc, f.m, f.b, auth.Chain{}, nil, &cfg, Options{Clock: f.clock.NowFunc()})
	mux := s.OpsMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()
	resp, _ := ts.Client().Get(ts.URL + "/readyz")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("readyz %d", resp.StatusCode)
	}
	s.draining.Store(true)
	resp, _ = ts.Client().Get(ts.URL + "/readyz")
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("draining readyz %d", resp.StatusCode)
	}
}

func BenchmarkChunkPUTParallel(b *testing.B) {
	f := setupT(b)
	defer f.srv.Close()
	f.token = f.tokenForB(b, "u", []string{"read", "write"}, nil)
	data := bytes.Repeat([]byte{9}, 1<<20)
	h := api.HashBytes(data)
	hx := hex.EncodeToString(h[:])
	resp := f.doB(b, "POST", "/v1/apps/a/slots/s/snapshots", manifestJSON(api.File{
		Path: "f", Size: int64(len(data)), Chunks: []api.ChunkRef{{Hash: h, Size: uint32(len(data))}},
	}), nil)
	var br2 struct {
		ChunkURL string `json:"chunk_url"`
	}
	json.NewDecoder(resp.Body).Decode(&br2)
	resp.Body.Close()
	url := f.srv.URL + br2.ChunkURL + hx
	b.SetBytes(int64(len(data)))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
			req.Header.Set("Authorization", "Bearer "+f.token)
			req.ContentLength = int64(len(data))
			resp, err := f.cli.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// TestDownloadSanity moves 64 MiB through plain GET and Range GETs and
// reports throughput.
func TestDownloadSanity(t *testing.T) {
	f := setup(t)
	f.token = f.tokenFor(t, "dl", []string{"read", "write"}, nil)
	const n = 64 << 20
	const csz = 2 << 20
	var refs []api.ChunkRef
	var parts [][]byte
	for off := 0; off < n; off += csz {
		c := bytes.Repeat([]byte{byte(off >> 20)}, csz)
		parts = append(parts, c)
		refs = append(refs, api.ChunkRef{Hash: api.HashBytes(c), Size: csz})
	}
	resp := f.do(t, "POST", "/v1/apps/a/slots/s/snapshots", manifestJSON(api.File{
		Path: "big", Size: n, Chunks: refs}), nil)
	var br struct {
		ID       string `json:"id"`
		ChunkURL string `json:"chunk_url"`
	}
	json.NewDecoder(resp.Body).Decode(&br)
	resp.Body.Close()
	for _, c := range parts {
		hh := api.HashBytes(c)
		hx := hex.EncodeToString(hh[:])
		put, _ := http.NewRequest("PUT", f.srv.URL+br.ChunkURL+hx, bytes.NewReader(c))
		put.Header.Set("Authorization", "Bearer "+f.token)
		put.ContentLength = csz
		r2, err := f.cli.Do(put)
		if err != nil || r2.StatusCode != 201 {
			t.Fatalf("put %v %d", err, r2.StatusCode)
		}
		r2.Body.Close()
	}
	cm, _ := http.NewRequest("POST", f.srv.URL+"/v1/apps/a/slots/s/snapshots/"+br.ID+"/commit", nil)
	cm.Header.Set("Authorization", "Bearer "+f.token)
	cm.Header.Set("If-Match", `""`)
	r3, _ := f.cli.Do(cm)
	if r3 != nil {
		r3.Body.Close()
	}
	url := f.srv.URL + "/v1/apps/a/slots/s/snapshots/" + br.ID + "/files/big"
	t0 := time.Now()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	got, err := f.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, got.Body)
	got.Body.Close()
	dt := time.Since(t0)
	t.Logf("plain GET 64MiB: %v = %.0f MB/s", dt, float64(n)/dt.Seconds()/(1<<20))
	// Ranged, 4 MiB chunks.
	t0 = time.Now()
	const step = 4 << 20
	for off := int64(0); off < n; off += step {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+f.token)
		req.Header.Set("Range", "bytes="+fmt64(off)+"-"+fmt64(off+step-1))
		resp, err := f.cli.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	dt = time.Since(t0)
	t.Logf("ranged GET 64MiB: %v = %.0f MB/s", dt, float64(n)/dt.Seconds()/(1<<20))
}

func fmt64(n int64) string { return strconv.FormatInt(n, 10) }
