// SPDX-License-Identifier: 0BSD

// Package nettest provides loopback transports with enlarged socket
// buffers for tests and benchmarks. On loopback the kernel auto-tuning
// window can collapse to tens of kilobytes against the large loopback
// MSS, which stalls bulk transfers for seconds at a time; a fixed 4 MiB
// buffer removes that artifact.
package nettest

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

const bufSize = 4 << 20

// LoopbackDialer returns a dialer with 4 MiB socket buffers.
func LoopbackDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, bufSize)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufSize)
			})
			return nil
		},
	}
}

// LoopbackTransport returns a transport for bulk loopback transfers.
func LoopbackTransport(insecureTLS bool) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = LoopbackDialer().DialContext
	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- test-only loopback
	}
	return tr
}

var _ = netip.Addr{}
