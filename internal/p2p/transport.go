// SPDX-License-Identifier: 0BSD

package p2p

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Listener wraps a QUIC listener serving the hub handler over http3.
type Listener struct {
	ln   *quic.Listener
	h3   *http3.Server
	conn net.PacketConn
}

// Listen serves h on a QUIC socket with pinned mutual TLS; the peer
// device id lands in request context via X-Saves-Device.
func Listen(conn net.PacketConn, id *Identity, peers *PeerSet, h http.Handler) (*Listener, error) {
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Saves-Device")
		dev := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
				dev = DeviceID(pub)
				r.Header.Set("X-Saves-Device", dev)
			}
		}
		if dev != "" {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, dev))
		}
		h.ServeHTTP(w, r)
	})
	tc := http3.ConfigureTLSConfig(id.TLSConfig(peers, true))
	ln, err := quic.Listen(conn, tc, &quic.Config{})
	if err != nil {
		return nil, err
	}
	l := &Listener{ln: ln, conn: conn, h3: &http3.Server{Handler: wrapped}}
	go l.h3.ServeListener(ln)
	return l, nil
}

type ctxKey struct{}

// Close stops the listener.
func (l *Listener) Close() error { return l.ln.Close() }

// Addr of the listener.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// NewTransport returns an http3 RoundTripper to a peer by device id.
// Transport is the client-side http.RoundTripper to a peer.
type Transport interface {
	http.RoundTripper
	Close() error
}

// NewTransport returns an http3 Transport to a peer by device id,
// failing over across addrs and reconnecting on error.
func NewTransport(id *Identity, peers *PeerSet, wantID string, addrs []string) (Transport, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("p2p: no address for peer")
	}
	cfg := http3.ConfigureTLSConfig(id.TLSConfig(peers, false))
	return &rewritingTransport{rt: &http3.Transport{TLSClientConfig: cfg},
		addrs: append([]string{}, addrs...)}, nil
}

// rewritingTransport forces the request to the peer address.
type rewritingTransport struct {
	rt    *http3.Transport
	addrs []string
	mu    sync.Mutex
	cur   int
}

func (t *rewritingTransport) Close() error { _ = t.rt.Close(); return nil }

func (t *rewritingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	for i := 0; i < len(t.addrs); i++ {
		t.mu.Lock()
		a := t.addrs[(t.cur+i)%len(t.addrs)]
		t.mu.Unlock()
		r2 := r.Clone(r.Context())
		r2.URL.Scheme = "https"
		r2.URL.Host = a
		resp, err := t.rt.RoundTrip(r2)
		if err == nil {
			t.mu.Lock()
			t.cur = (t.cur + i) % len(t.addrs)
			t.mu.Unlock()
			return resp, nil
		}
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		default:
		}
	}
	return nil, fmt.Errorf("p2p: no reachable address")
}
