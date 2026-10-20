// SPDX-License-Identifier: 0BSD

package netx

import (
	"net/http"
	"net/netip"
	"testing"
)

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestClientIP(t *testing.T) {
	trust := []netip.Prefix{mustPrefix("10.0.0.0/8")}
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:1"
	if got := ClientIP(r, trust); got.String() != "203.0.113.9" {
		t.Fatal("untrusted peer uses RemoteAddr")
	}
	r.RemoteAddr = "10.1.2.3:1"
	r.Header.Set("X-Forwarded-For", "8.8.8.8, 10.9.9.9, 192.0.2.7")
	// Rightmost untrusted wins: 192.0.2.7.
	if got := ClientIP(r, trust); got.String() != "192.0.2.7" {
		t.Fatalf("xff: %s", got)
	}
	// Malformed header falls back to peer.
	r.Header.Set("X-Forwarded-For", "garbage")
	if got := ClientIP(r, trust); got.String() != "10.1.2.3" {
		t.Fatalf("garbage: %s", got)
	}
	// Prefixes.
	if got := IPPrefix(netip.MustParseAddr("2001:db8::1")); got != "2001:db8::/64" {
		t.Fatalf("v6 prefix %s", got)
	}
	if got := IPPrefix(netip.MustParseAddr("192.0.2.1")); got != "192.0.2.1/32" {
		t.Fatalf("v4 prefix %s", got)
	}
}

func FuzzClientIP(f *testing.F) {
	f.Add("10.0.0.1:80", "8.8.8.8, 1.1.1.1")
	f.Add("x", "")
	f.Fuzz(func(t *testing.T, remote, xff string) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		_ = ClientIP(r, []netip.Prefix{mustPrefix("10.0.0.0/8"), mustPrefix("::/0")})
		_ = IPPrefix(ClientIP(r, nil))
	})
}
