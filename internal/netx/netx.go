// SPDX-License-Identifier: 0BSD

// Package netx provides listeners, dialers, and transports with
// Multipath TCP disabled. Landlock network rules do not cover MPTCP, so
// every socket the process opens must go through these helpers for
// sandbox policy to apply.
package netx

import (
	"context"
	"net"
	"net/http"
	"syscall"
	"time"
)

// ListenConfig returns a net.ListenConfig with Multipath TCP disabled.
func ListenConfig() *net.ListenConfig {
	lc := &net.ListenConfig{}
	lc.SetMultipathTCP(false)
	return lc
}

// Listen is net.Listen with Multipath TCP disabled.
func Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	return ListenConfig().Listen(ctx, network, addr)
}

// Dialer returns a net.Dialer with Multipath TCP disabled.
func Dialer() *net.Dialer {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	d.SetMultipathTCP(false)
	return d
}

// NewTransport returns an http.Transport that dials with Multipath TCP
// disabled.
func NewTransport() *http.Transport {
	return &http.Transport{
		DialContext:           Dialer().DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// ListenUDP opens a UDP packet socket through net.ListenConfig so the
// Landlock BindUDP path is centralized. BufferBytes best-effort sets
// SO_RCVBUF and SO_SNDBUF; quic-go wants at least 7 MiB.
func ListenUDP(ctx context.Context, addr string, bufferBytes int) (net.PacketConn, error) {
	lc := &net.ListenConfig{}
	if bufferBytes > 0 {
		lc.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			_ = c.Control(func(fd uintptr) {
				setBuf(fd, bufferBytes)
			})
			return serr
		}
	}
	return lc.ListenPacket(ctx, "udp", addr)
}
