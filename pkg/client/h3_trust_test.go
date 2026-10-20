// SPDX-License-Identifier: 0BSD

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// TestH3Trust verifies HTTP3 mode honors Config.TLS.
func TestH3Trust(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := tls.X509KeyPair(pemEncode("CERTIFICATE", der),
		pemEncode("PRIVATE KEY", marshalPKCS8(t, k)))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	srv := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	})}
	ln, err := quic.Listen(pc, http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{crt}, MinVersion: tls.VersionTLS13,
	}), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.ServeListener(ln)
	addr := ln.Addr().String()
	// untrusted: self-signed must fail
	c1, err := New(Config{BaseURL: "https://" + addr, HTTP3: true,
		TLS: &tls.Config{ServerName: "localhost"}}) // #nosec G402
	if err != nil {
		t.Fatal(err)
	}
	_, err = c1.Me(context.Background())
	if err == nil {
		t.Fatal("untrusted self-signed accepted")
	}
	// trusted via RootCAs
	pool := x509.NewCertPool()
	pool.AddCert(func() *x509.Certificate { c, _ := x509.ParseCertificate(der); return c }())
	c2, err := New(Config{BaseURL: "https://" + addr, HTTP3: true,
		TLS: &tls.Config{RootCAs: pool, ServerName: "localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://"+addr+"/v1/me", nil)
	r2 := &http.Client{Transport: c2.h3}
	resp, err := r2.Do(req)
	if err != nil {
		t.Fatal("trusted h3:", err)
	}
	resp.Body.Close()
}

func pemEncode(typ string, b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})
}

func marshalPKCS8(t *testing.T, k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
