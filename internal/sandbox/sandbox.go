// SPDX-License-Identifier: 0BSD

// Package sandbox confines savesd with Linux Landlock.
//
// Listeners are opened before Apply so bind rules only need to cover
// outbound connects; rebinds after SIGHUP still work because bound
// sockets are already held.
package sandbox

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/Sudo-Ivan/saves/internal/config"
)

// Policy is the resolved Landlock rule set.
type Policy struct {
	RODirs     []string
	ROFiles    []string
	RWDirs     []string
	RWFiles    []string
	ConnectTCP []uint16
	BindTCP    []uint16
	ConnectUDP []uint16
	Scoped     bool
}

// Report describes what Apply achieved.
type Report struct {
	ABI       int
	FS        bool
	TCP       bool
	UDP       bool
	Scoped    bool
	Mode      string
	Supported bool
}

// FromConfig builds a Policy from config and resolved runtime paths.
func FromConfig(c *config.Config, configPath string) (*Policy, error) {
	p := &Policy{Scoped: true}
	addRW := func(d string) {
		if d == "" || d == "/" || !filepath.IsAbs(d) {
			return
		}
		p.RWDirs = append(p.RWDirs, filepath.Clean(d))
	}
	switch c.Storage.Blob.Driver {
	case "fs":
		addRW(c.Storage.Blob.FS.Root)
	}
	if c.Storage.Meta.Driver == "sqlite" {
		addRW(filepath.Dir(c.Storage.Meta.SQLite.Path))
	} else if c.Storage.Meta.Driver == "postgres" {
		addPort(&p.ConnectTCP, pgPort(c.Storage.Meta.Postgres.DSN))
	}
	if c.Storage.Blob.Driver == "s3" {
		addPort(&p.ConnectTCP, urlPort(c.Storage.Blob.S3.Endpoint, 443, 80))
	}
	// Data dirs the process must write.
	p.RODirs = []string{"/usr/share/zoneinfo", "/etc/ssl/certs", "/proc"}
	p.ROFiles = []string{"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"}
	if configPath != "" {
		p.RODirs = append(p.RODirs, filepath.Dir(configPath))
	}
	if c.Listen.TLS.CertFile != "" {
		p.RODirs = append(p.RODirs, filepath.Dir(c.Listen.TLS.CertFile))
		if c.Listen.TLS.KeyFile != "" {
			p.RODirs = append(p.RODirs, filepath.Dir(c.Listen.TLS.KeyFile))
		}
	}
	if c.Listen.TLS.Mode == "acme" {
		addRW(c.Listen.TLS.ACME.CacheDir)
		addPort(&p.ConnectTCP, 443)
	}
	if c.Auth.OIDC.Issuer != "" {
		addPort(&p.ConnectTCP, urlPort(c.Auth.OIDC.Issuer, 443, 443))
	}
	addPort(&p.ConnectTCP, 53) // DNS
	p.ConnectUDP = []uint16{53}
	// Bound sockets must survive the net restriction.
	for _, addr := range []string{c.Listen.Addr, c.Ops.Addr} {
		if addr == "" {
			continue
		}
		_, port, err := net.SplitHostPort(addr)
		if err == nil {
			var pi int
			fmt.Sscanf(port, "%d", &pi)
			if pi > 0 {
				addPort(&p.BindTCP, uint16(pi))
			}
		}
	}
	p.RODirs = append(p.RODirs, cleanPaths(c.Sandbox.ExtraROPaths)...)
	p.RWDirs = append(p.RWDirs, cleanPaths(c.Sandbox.ExtraRWPaths)...)
	p.ConnectTCP = append(p.ConnectTCP, c.Sandbox.ExtraConnectTCPPorts...)
	p.BindTCP = append(p.BindTCP, c.Sandbox.ExtraBindTCPPorts...)
	return p, nil
}

// cleanPaths drops empty, relative, and root paths.
func cleanPaths(in []string) []string {
	var out []string
	for _, p := range in {
		if p == "" || p == "/" || !filepath.IsAbs(p) {
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

func addPort(ports *[]uint16, v uint16) {
	for _, x := range *ports {
		if x == v {
			return
		}
	}
	*ports = append(*ports, v)
}

func pgPort(dsn string) uint16 {
	if i := strings.LastIndex(dsn, "port="); i >= 0 {
		var p int
		if _, err := fmt.Sscanf(dsn[i+5:], "%d", &p); err == nil && p > 0 {
			return uint16(p)
		}
	}
	return 5432
}

func urlPort(u string, defTLS, defPlain uint16) uint16 {
	if i := strings.LastIndex(u, ":"); i >= 0 {
		var p int
		if _, err := fmt.Sscanf(u[i+1:], "%d", &p); err == nil && p > 0 {
			return uint16(p)
		}
	}
	if strings.HasPrefix(u, "https") || strings.HasPrefix(u, "wss") {
		return defTLS
	}
	return defPlain
}
