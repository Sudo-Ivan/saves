// SPDX-License-Identifier: 0BSD

// Package p2p implements device to device save syncing over QUIC.
package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// DeviceID is base32(SHA-256(pubkey)).
func DeviceID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:])[:52]
}

// Identity is this device's key and cert.
type Identity struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
	ID   string
	Cert tls.Certificate
}

// LoadIdentity generates or loads <dir>/device.key (0600).
func LoadIdentity(dir string) (*Identity, error) {
	p := filepath.Join(dir, "device.key")
	if b, err := os.ReadFile(p); err == nil && len(b) == ed25519.SeedSize {
		priv := ed25519.NewKeyFromSeed(b)
		return makeIdentity(priv)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, priv.Seed(), 0o600); err != nil {
		return nil, err
	}
	return makeIdentity(priv)
}

func makeIdentity(priv ed25519.PrivateKey) (*Identity, error) {
	pub := priv.Public().(ed25519.PublicKey)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "saves-device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, pub, priv)
	if err != nil {
		return nil, err
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pk8, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8})
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}
	return &Identity{Priv: priv, Pub: pub, ID: DeviceID(pub), Cert: cert}, nil
}

// TLSConfig pins peers by public key (mutual, no CA).
func (id *Identity) TLSConfig(peers *PeerSet, isServer bool) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		NextProtos:   []string{"saves-p2p/1"},
		MinVersion:   tls.VersionTLS13,
	}
	if isServer {
		cfg.ClientAuth = tls.RequireAnyClientCert
	} else {
		cfg.InsecureSkipVerify = true
	}
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		c, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		pub, ok := c.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("p2p: peer cert is not ed25519")
		}
		if peers != nil && peers.Has(DeviceID(pub)) {
			return nil
		}
		return errors.New("p2p: peer not trusted")
	}
	return cfg
}

// PairingTLSConfig accepts any cert; caller pins after pairing.
func (id *Identity) PairingTLSConfig(isServer bool) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		NextProtos:   []string{"saves-p2p/1"},
		MinVersion:   tls.VersionTLS13,
	}
	if isServer {
		cfg.ClientAuth = tls.RequireAnyClientCert
	} else {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}
