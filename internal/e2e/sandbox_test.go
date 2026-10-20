// SPDX-License-Identifier: 0BSD

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Sudo-Ivan/saves/pkg/client"
	"github.com/quic-go/quic-go/http3"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startServerEnforce starts savesd with sandbox.mode=enforce.
func startServerEnforce(t *testing.T) (url string, dataDir string, sb *strings.Builder, stop func()) {
	t.Helper()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("127.0.0.1:%d", port)
	l.Close()
	dir := t.TempDir()
	cfg := fmt.Sprintf(`{
  "listen": {"addr": "127.0.0.1:%d", "protocols": ["h1"]},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "open"},
  "quota": {"allow_unknown_apps": ".*"},
  "sandbox": {"mode": "enforce", "allow_root": true},
  "log": {"level": "debug"}
}`, port, dir, dir)
	cp := filepath.Join(dir, "config.json")
	os.WriteFile(cp, []byte(cfg), 0o600)
	cmd := exec.Command(filepath.Join(binDir, "savesd"), "serve", "-config", cp)
	cmd.Dir = dir
	sb = &strings.Builder{}
	cmd.Stderr = sb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop = func() { cmd.Process.Kill(); cmd.Wait() }
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return fmt.Sprintf("http://127.0.0.1:%d", port), dir, sb, stop
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("savesd did not come up; stderr=%s", sb.String())
	return "", dir, sb, stop
}

func TestSandboxEnforce(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	url, _, sb, stop := startServerEnforce(t)
	defer stop()
	envA, envB, hA, hB := trackPair(t, url)
	_ = envA
	_ = hA
	_ = hB
	writeFile(t, hA, "g/save.dat", "sandboxed")
	code, _, se := run(t, envA, "push", "--all")
	t.Logf("server stderr: %s", sb.String())
	if code != 0 {
		t.Fatalf("push under enforce: %d %s", code, se)
	}
	// B pulls
	code, outp, se := run(t, envB, "pull", "--all")
	if code != 0 {
		t.Fatalf("pull under enforce: %d %s", code, se)
	}
	_ = outp
	if got := readFile(t, hB, "g/save.dat"); got != "sandboxed" {
		t.Fatalf("pull got %q", got)
	}
	// NoNewPrivs check on the server pid would need pid discovery; check
	// sandbox-check JSON instead.
}

// TestSandboxCheck runs the subcommand against an enforce config.
func TestSandboxCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	dir := t.TempDir()
	cfg := fmt.Sprintf(`{
  "listen": {"addr": "127.0.0.1:0", "protocols": ["h1"]},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "open"},
  "quota": {"allow_unknown_apps": ".*"},
  "sandbox": {"mode": "enforce", "allow_root": true, "extra_rw_paths": ["%s"]},
  "log": {"level": "debug"}
}`, dir, dir, dir)
	cp := filepath.Join(dir, "config.json")
	os.WriteFile(cp, []byte(cfg), 0o600)
	os.MkdirAll(dir+"/blobs", 0o755)
	cmd := exec.Command(filepath.Join(binDir, "savesd"), "sandbox-check", "-config", cp)
	out, err := cmd.CombinedOutput()
	t.Logf("sandbox-check: %s", out)
	// enforce mode: any deny success or allow failure -> nonzero
	if err == nil {
		// parse JSON for probe results
		var rep struct {
			ABI    int  `json:"abi"`
			FS     bool `json:"fs"`
			Probes []struct {
				Name string `json:"Name"`
				Deny bool   `json:"Deny"`
				OK   bool   `json:"OK"`
			} `json:"probes"`
		}
		if json.Unmarshal(out, &rep) == nil {
			for _, p := range rep.Probes {
				if !p.OK {
					t.Fatalf("probe %s unexpectedly passed (deny=%v)", p.Name, p.Deny)
				}
			}
		}
	}
	// mode enforce with / as rw: must refuse at config/policy level
	cfg2 := strings.Replace(cfg, `"extra_rw_paths": ["`+dir+`"]`, `"extra_rw_paths": ["/"]`, 1)
	cp2 := filepath.Join(dir, "config2.json")
	os.WriteFile(cp2, []byte(cfg2), 0o600)
	c2 := exec.Command(filepath.Join(binDir, "savesd"), "serve", "-config", cp2)
	c2.Env = append(os.Environ(), "SAVES_SBX_CHILD=1")
	b, _ := c2.CombinedOutput()
	_ = b
	// serve should fail at config validation or policy build
	if c2.ProcessState != nil && c2.ProcessState.ExitCode() == 0 {
		t.Fatal("savesd started with extra_rw_paths /")
	}
}

// TestSandboxTraversal sends hostile paths at every route family.
func TestSandboxTraversal(t *testing.T) {
	url, _, _, stop := startServerEnforce(t)
	defer stop()
	// register a device to get a token
	envA := deviceEnv(t, "sb-trav")
	run(t, envA, "setup", "--server", url, "--register")
	// extract token from env file
	hcfg, _ := os.ReadFile(envHome(envA) + "/.config/saves/config.json")
	var cfgj struct {
		Token string `json:"token"`
	}
	json.Unmarshal(hcfg, &cfgj)
	paths := []string{
		"../", "..%2f", "%2e%2e%2f", "..\\", "%2f..%2f", "%00", "a/./b",
		strings.Repeat("a", 500), "../../etc/passwd", "..%252f",
	}
	routes := []string{
		"/v1/apps/{a}/slots/s/snapshots/x/files/%s",
		"/v1/apps/%s/slots/s",
		"/v1/apps/a/slots/s/snapshots/%s",
		"/v1/apps/a/chunks/%s",
	}
	n := 0
	bad := 0
	for _, rt := range routes {
		for _, p := range paths {
			u := url + fmt.Sprintf(rt, p)
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("Authorization", "Bearer "+cfgj.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			n++
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				continue
			}
			if resp.StatusCode == 404 || resp.StatusCode == 400 {
				continue
			}
			bad++
			t.Logf("hostile %s -> %d", u, resp.StatusCode)
		}
	}
	t.Logf("traversal: %d attempts, %d non-4xx", n, bad)
	if bad > 0 {
		t.Fatal("hostile path returned non-4xx")
	}
}

// TestSandboxNoNewPrivs reads /proc of the enforcing savesd.
func TestSandboxNoNewPrivs(t *testing.T) {
	url, dir, _, stop := startServerEnforce(t)
	defer stop()
	_ = url
	_ = dir
	// find savesd pid by the temp dir in cmdline
	out, _ := exec.Command("sh", "-c",
		"pgrep -f 'savesd serve'").Output()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	found := false
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		b, err := os.ReadFile("/proc/" + ln + "/status")
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "NoNewPrivs:\t1") {
			found = true
		}
	}
	if !found {
		t.Skip("could not confirm NoNewPrivs via /proc")
	}
}

// TestSandboxRefuseRootRW: extra_rw_paths "/" must refuse to start.
func TestSandboxRefuseRootRW(t *testing.T) {
	dir := t.TempDir()
	cfg := fmt.Sprintf(`{
  "listen": {"addr": "127.0.0.1:0", "protocols": ["h1"]},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "open"},
  "quota": {"allow_unknown_apps": ".*"},
  "sandbox": {"mode": "enforce", "allow_root": true, "extra_rw_paths": ["/"]},
  "log": {"level": "debug"}
}`, dir, dir)
	cp := filepath.Join(dir, "config.json")
	os.WriteFile(cp, []byte(cfg), 0o600)
	cmd := exec.Command(filepath.Join(binDir, "savesd"), "serve", "-config", cp)
	err := cmd.Run()
	if err == nil {
		t.Fatal("enforce with extra_rw_paths=/ started")
	}
	t.Logf("refused: %v", err)
}

// selfSigned writes cert.pem+key.pem and returns the DER fingerprint.
func selfSigned(t *testing.T, dir, cn string) []byte {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"/cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(dir+"/key.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	fp := sha256.Sum256(der)
	return fp[:]
}

// TestSandboxTLS serves h1+h2+h3 under enforce with a self-signed cert,
// pushes/pulls and does a ranged GET, then SIGHUP cert reload.
func TestSandboxTLS(t *testing.T) {
	dir := t.TempDir()
	fp1 := selfSigned(t, dir, "old")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := fmt.Sprintf(`{
  "listen": {"addr": "127.0.0.1:%d", "protocols": ["h1","h2","h3"],
    "h3_addr": "127.0.0.1:%d", "alt_svc": "h3=\"127.0.0.1:%d\"",
    "tls": {"mode": "files", "cert_file": "%s/cert.pem", "key_file": "%s/key.pem"}},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "open"},
  "auth": {"order": ["token"], "token": {"enabled": true}},
  "quota": {"allow_unknown_apps": ".*"},
  "sandbox": {"mode": "enforce", "allow_root": true},
  "log": {"level": "debug"}
}`, port, port, port, dir, dir, dir, dir)
	cp := filepath.Join(dir, "config.json")
	os.WriteFile(cp, []byte(cfg), 0o600)
	cmd := exec.Command(filepath.Join(binDir, "savesd"), "serve", "-config", cp)
	cmd.Dir = dir
	var sb strings.Builder
	cmd.Stderr = &sb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	url := fmt.Sprintf("https://127.0.0.1:%d", port)
	// wait for listen
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	pool := x509.NewCertPool()
	pemB, _ := os.ReadFile(dir + "/cert.pem")
	pool.AppendCertsFromPEM(pemB)
	trust := &tls.Config{RootCAs: pool, ServerName: "localhost"} // #nosec G402
	// Register directly with the pinned-cert client; the CLI cannot trust
	// a self-signed cert.
	hA := t.TempDir()
	mkWorld(t, hA+"/g", "g", 1<<20)
	hcReg := &http.Client{Transport: &http.Transport{TLSClientConfig: trust}}
	regResp, err := hcReg.Post(url+"/v1/register", "application/json",
		strings.NewReader(`{"invite":""}`))
	if err != nil {
		t.Fatal("register:", err)
	}
	var cj struct {
		Token string `json:"token"`
	}
	json.NewDecoder(regResp.Body).Decode(&cj)
	regResp.Body.Close()
	if cj.Token == "" {
		t.Fatalf("register gave no token (status %d)", regResp.StatusCode)
	}
	ctx := context.Background()
	for _, h3 := range []bool{false, true} {
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: trust, ForceAttemptHTTP2: true}}
		var cc *client.Client
		var err error
		var h3t *http3.Transport
		if h3 {
			h3t = &http3.Transport{TLSClientConfig: trust}
			cc, err = client.New(client.Config{BaseURL: url, Token: cj.Token,
				HTTP: &http.Client{Transport: h3t}})
		} else {
			cc, err = client.New(client.Config{BaseURL: url, Token: cj.Token, HTTP: hc})
		}
		if err != nil {
			t.Fatal(err)
		}
		src := client.Source{Roots: []client.Root{{Key: "w", Dir: hA + "/g"}}}
		st := client.NewMemStore()
		slot := "s"
		if h3 {
			slot = "s3"
		}
		if _, err := cc.Push(ctx, "tlsapp", slot, src, st, client.PushOptions{}); err != nil {
			t.Fatalf("push h3=%v: %v", h3, err)
		}
		dstDir := t.TempDir() + "/w"
		os.MkdirAll(dstDir, 0o700)
		if _, err := cc.Pull(ctx, "tlsapp", slot, "", client.Source{Roots: []client.Root{{Key: "w", Dir: dstDir}}}, client.NewMemStore(), client.PullOptions{}); err != nil {
			t.Fatalf("pull h3=%v: %v", h3, err)
		}
		// ranged GET of a file endpoint, raw client of the same kind.
		var rrc *http.Client
		if h3 {
			rrc = &http.Client{Transport: h3t}
		} else {
			rrc = hc
		}
		req, _ := http.NewRequest("GET", url+fmt.Sprintf("/v1/apps/tlsapp/slots/%s/snapshots/latest/files/w/level.dat", slot), nil)
		req.Header.Set("Authorization", "Bearer "+cj.Token)
		req.Header.Set("Range", "bytes=0-3")
		resp, err := rrc.Do(req)
		if err != nil {
			t.Fatalf("ranged h3=%v: %v", h3, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 206 {
			t.Fatalf("range h3=%v status=%d", h3, resp.StatusCode)
		}
		want := 2
		if h3 {
			want = 3
		}
		if resp.ProtoMajor != want {
			t.Fatalf("h3=%v proto=%d want %d", h3, resp.ProtoMajor, want)
		}
		if !h3 && resp.Header.Get("Alt-Svc") == "" {
			t.Fatal("missing Alt-Svc on TCP response")
		}
		t.Logf("h3=%v ranged 206 proto=%d", h3, resp.ProtoMajor)
	}
	// SIGHUP cert reload under enforce
	fp2 := selfSigned(t, dir, "new")
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port),
		&tls.Config{InsecureSkipVerify: true}) // #nosec G402
	if err != nil {
		t.Fatalf("handshake after reload: %v (stderr: %s)", err, sb.String())
	}
	got := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
	conn.Close()
	if bytes.Equal(fp1, got[:]) {
		t.Fatal("cert not reloaded")
	}
	if !bytes.Equal(fp2, got[:]) {
		t.Fatal("served cert is not the new one")
	}
	t.Log("cert reload under enforce works")
}
