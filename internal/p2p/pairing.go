// SPDX-License-Identifier: 0BSD

package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const pairALPN = "saves-pair/1"

// PairOptions tune host pairing.
type PairOptions struct {
	Name         string
	ServiceAddrs []string
	TTL          time.Duration
	MaxAttempts  int
}

// PairResult is what the joiner gets.
type PairResult struct {
	HostID, HostName, Token string
	Addrs                   []string
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// parseCode normalizes a typed code back to 16 bytes.
func parseCode(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "_", "").Replace(s))
	b, err := b32.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, errors.New("p2p: bad pairing code")
	}
	return b, nil
}

// makeCode renders 16 random bytes as grouped base32.
func makeCode() (string, []byte) {
	b := make([]byte, 16)
	rand.Read(b)
	s := b32.EncodeToString(b)
	var g []string
	for i := 0; i < len(s); i += 4 {
		e := i + 4
		if e > len(s) {
			e = len(s)
		}
		g = append(g, s[i:e])
	}
	return strings.Join(g, "-"), b
}

// certFP is SHA-256 of the peer's presented cert DER.
func certFP(c *x509.Certificate) [32]byte { return sha256.Sum256(c.Raw) }

// mac computes the pairing confirmation MAC.
func mac(code, fpA, fpB, nH, nJ []byte, role byte) []byte {
	fps := [][]byte{fpA, fpB}
	sort.Slice(fps, func(i, j int) bool { return string(fps[i]) < string(fps[j]) })
	h := hmac.New(sha256.New, code)
	h.Write([]byte("saves-pair-v1"))
	h.Write(fps[0])
	h.Write(fps[1])
	h.Write(nH)
	h.Write(nJ)
	h.Write([]byte{role})
	return h.Sum(nil)
}

func writeMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > 4096 {
		return errors.New("p2p: pairing message too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b))) // #nosec G115 -- value bounded by the format or by max_chunk_bytes
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readMsg(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 4096 {
		return errors.New("p2p: pairing message too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func hostCert(id *Identity) *x509.Certificate {
	c, _ := x509.ParseCertificate(id.Cert.Certificate[0])
	return c
}

func pairTLS(id *Identity, server bool) *tls.Config {
	cfg := &tls.Config{Certificates: []tls.Certificate{id.Cert},
		NextProtos: []string{pairALPN}, MinVersion: tls.VersionTLS13}
	if server {
		cfg.ClientAuth = tls.RequireAnyClientCert
	} else {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

// HostPair starts a pairing listener. wait returns the joined peer.
func HostPair(ctx context.Context, conn net.PacketConn, id *Identity, peers *PeerSet,
	mint func(name string) (string, error), opt PairOptions) (code string, wait func() (Peer, error), err error) {
	code, codeB := makeCode()
	ttl := opt.TTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	maxA := opt.MaxAttempts
	if maxA == 0 {
		maxA = 3
	}
	ln, err := quic.Listen(conn, pairTLS(id, true), &quic.Config{})
	if err != nil {
		return "", nil, err
	}
	done := make(chan Peer, 1)
	errCh := make(chan error, 1)
	var attempts int64
	go func() {
		defer ln.Close()
		ctx2, cancel := context.WithTimeout(ctx, ttl)
		defer cancel()
		var busy atomic.Bool
		for {
			c, err := ln.Accept(ctx2)
			if err != nil {
				select {
				case errCh <- fmt.Errorf("p2p: pairing accept: %w", err):
				default:
				}
				return
			}
			if !busy.CompareAndSwap(false, true) {
				_ = c.CloseWithError(1, "busy")
				continue
			}
			go func(c *quic.Conn) {
				defer busy.Store(false)
				if atomic.AddInt64(&attempts, 1) > int64(maxA) {
					_ = c.CloseWithError(2, "attempts")
					return
				}
				if p, err := hostHandshake(ctx2, c, codeB, opt.Name, opt.ServiceAddrs, mint, hostCert(id)); err == nil {
					_ = peers.Add(p)
					done <- p
					// single use: stop the listener after success.
					go ln.Close()
				}
			}(c)
		}
	}()
	return code, func() (Peer, error) {
		select {
		case p := <-done:
			return p, nil
		case err := <-errCh:
			return Peer{}, err
		case <-ctx.Done():
			return Peer{}, ctx.Err()
		}
	}, nil
}

// hostHandshake runs the host side on an accepted conn.
func hostHandshake(ctx context.Context, c *quic.Conn, code []byte, myName string, addrs []string,
	mint func(string) (string, error), myCertDER *x509.Certificate) (Peer, error) {
	st, err := c.AcceptStream(ctx)
	if err != nil {
		return Peer{}, err
	}
	_ = st.SetDeadline(time.Now().Add(30 * time.Second))
	// first message: joiner nonce+name
	var msg1 struct {
		Nonce string `json:"n"`
		Name  string `json:"name"`
	}
	if err := readMsg(st, &msg1); err != nil {
		return Peer{}, err
	}
	nJ, _ := b32.DecodeString(strings.ToUpper(msg1.Nonce))
	nonce := make([]byte, 16)
	rand.Read(nonce)
	var peerFP [32]byte
	if cs := c.ConnectionState().TLS; len(cs.PeerCertificates) > 0 {
		peerFP = certFP(cs.PeerCertificates[0])
	} else {
		return Peer{}, errors.New("p2p: no peer cert")
	}
	// own cert fp from the cert we presented
	var myFP [32]byte
	if myCertDER != nil {
		myFP = certFP(myCertDER)
	}
	macH := mac(code, myFP[:], peerFP[:], nonce, nJ, 'H')
	if err := writeMsg(st, map[string]string{
		"n": b32.EncodeToString(nonce), "name": myName,
		"mac": b32.EncodeToString(macH)}); err != nil {
		return Peer{}, err
	}
	var msg2 struct {
		Mac string `json:"mac"`
	}
	if err := readMsg(st, &msg2); err != nil {
		return Peer{}, err
	}
	macJB, _ := b32.DecodeString(strings.ToUpper(msg2.Mac))
	wantJ := mac(code, myFP[:], peerFP[:], nonce, nJ, 'J')
	if subtle.ConstantTimeCompare(macJB, wantJ) != 1 {
		return Peer{}, errors.New("p2p: mac mismatch")
	}
	// host verified: joiner's mac proves it has the code; host's mac in msg1 reply
	// lets the joiner verify the host. Both verified -> mint + send token.
	tok, err := mint(msg1.Name)
	if err != nil {
		return Peer{}, err
	}
	if err := writeMsg(st, map[string]string{"token": tok, "addrs": strings.Join(addrs, ",")}); err != nil {
		return Peer{}, err
	}
	pid := ""
	if pub, ok := c.ConnectionState().TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
		pid = DeviceID(pub)
	}
	return Peer{ID: pid, Name: msg1.Name,
		Addrs: []string{c.RemoteAddr().String()}, AddedAt: time.Now()}, nil
}

// JoinPair joins a host by code.
func JoinPair(ctx context.Context, id *Identity, peers *PeerSet, addr, code, name string) (PairResult, error) {
	codeB, err := parseCode(code)
	if err != nil {
		return PairResult{}, err
	}
	c, err := quic.DialAddr(ctx, addr, pairTLS(id, false), &quic.Config{})
	if err != nil {
		return PairResult{}, err
	}
	defer c.CloseWithError(0, "bye")
	st, err := c.OpenStreamSync(ctx)
	if err != nil {
		return PairResult{}, err
	}
	_ = st.SetDeadline(time.Now().Add(30 * time.Second))
	nonce := make([]byte, 16)
	rand.Read(nonce)
	if err := writeMsg(st, map[string]string{
		"n": b32.EncodeToString(nonce), "name": name}); err != nil {
		return PairResult{}, err
	}
	var msg1 struct {
		N, Name, Mac string `json:"-"`
	}
	var m1 map[string]string
	if err := readMsg(st, &m1); err != nil {
		return PairResult{}, err
	}
	msg1.N, msg1.Name, msg1.Mac = m1["n"], m1["name"], m1["mac"]
	nH, _ := b32.DecodeString(strings.ToUpper(msg1.N))
	var hostFP [32]byte
	cs := c.ConnectionState().TLS
	if len(cs.PeerCertificates) > 0 {
		hostFP = certFP(cs.PeerCertificates[0])
	}
	myCert, _ := x509.ParseCertificate(id.Cert.Certificate[0])
	myFP := certFP(myCert)
	macJB, _ := b32.DecodeString(strings.ToUpper(msg1.Mac))
	wantH := mac(codeB, myFP[:], hostFP[:], nH, nonce, 'H')
	if subtle.ConstantTimeCompare(macJB, wantH) != 1 {
		return PairResult{}, errors.New("p2p: host mac mismatch")
	}
	macJ := mac(codeB, myFP[:], hostFP[:], nH, nonce, 'J')
	if err := writeMsg(st, map[string]string{"mac": b32.EncodeToString(macJ)}); err != nil {
		return PairResult{}, err
	}
	var m2 map[string]string
	if err := readMsg(st, &m2); err != nil {
		return PairResult{}, err
	}
	hostID := ""
	if pub, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
		hostID = DeviceID(pub)
	}
	var svc []string
	for _, a := range strings.Split(m2["addrs"], ",") {
		if a = strings.TrimSpace(a); a != "" && len(svc) < 8 {
			svc = append(svc, fixAdvertised(a, addr))
		}
	}
	if len(svc) == 0 {
		svc = []string{addr}
	}
	_ = peers.Add(Peer{ID: hostID, Name: msg1.Name, Addrs: svc, AddedAt: time.Now()})
	return PairResult{HostID: hostID, HostName: msg1.Name, Token: m2["token"], Addrs: svc}, nil
}

// fixAdvertised replaces an unspecified host in an advertised address with
// the host the joiner dialed.
func fixAdvertised(adv, dialed string) string {
	ah, ap, err := net.SplitHostPort(adv)
	if err != nil {
		return adv
	}
	if ip := net.ParseIP(ah); ah == "" || (ip != nil && ip.IsUnspecified()) {
		if dh, _, err := net.SplitHostPort(dialed); err == nil {
			return net.JoinHostPort(dh, ap)
		}
	}
	return adv
}
