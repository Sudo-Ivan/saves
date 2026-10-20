// SPDX-License-Identifier: 0BSD

package netx

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP returns the real client IP honoring X-Forwarded-For only when
// the direct peer is inside trustedCIDRs. It walks XFF from the right:
// the first hop not in trusted CIDRs is the client. When the peer is not
// trusted, or no header exists, RemoteAddr wins.
func ClientIP(r *http.Request, trustedCIDRs []netip.Prefix) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	trusted := false
	for _, p := range trustedCIDRs {
		if p.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return peer
	}
	// Walk right to left skipping trusted proxies.
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer
		}
		ok := false
		for _, p := range trustedCIDRs {
			if p.Contains(a) {
				ok = true
				break
			}
		}
		if !ok {
			return a
		}
	}
	return peer
}

// IPPrefix returns the /32 (v4) or /64 (v6) prefix key for rate and
// identity bucketing.
func IPPrefix(a netip.Addr) string {
	if !a.IsValid() {
		return "unknown"
	}
	if a.Is4() {
		return a.String() + "/32"
	}
	return netip.PrefixFrom(a, 64).Masked().Addr().String() + "/64"
}
