// SPDX-License-Identifier: 0BSD

package sandbox

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// Probe is one deny or allow test run inside a re-execed child.
type Probe struct {
	Name  string
	Deny  bool
	OK    bool
	Notes string
}

// Child runs every probe then exits; invoked via re-exec.
func Child(pol *Policy, mode string) int {
	if err := Harden(true); err != nil {
		fmt.Println("harden:", err)
	}
	rep, err := Apply(pol, mode)
	if err != nil {
		fmt.Println("apply:", err)
		return 2
	}
	_ = rep
	var probes []Probe
	try := func(name string, deny bool, fn func() error) {
		err := fn()
		pr := Probe{Name: name, Deny: deny}
		if deny {
			pr.OK = err != nil
			pr.Notes = fmt.Sprint(err)
		} else {
			pr.OK = err == nil
			pr.Notes = fmt.Sprint(err)
		}
		probes = append(probes, pr)
	}
	home, _ := os.UserHomeDir()
	try("read /etc/shadow", true, func() error {
		_, e := os.ReadFile("/etc/shadow")
		return e
	})
	try("list home", true, func() error {
		_, e := os.ReadDir(home)
		return e
	})
	try("write /tmp", true, func() error {
		return os.WriteFile("/tmp/sbx-probe", []byte("x"), 0o600)
	})
	try("write /var/tmp", true, func() error {
		return os.WriteFile("/var/tmp/sbx-probe", []byte("x"), 0o600)
	})
	try("rename out of data dir", true, func() error {
		src := filepath.Join(os.TempDir(), "sbxsrc")
		os.WriteFile(src, []byte("x"), 0o600)
		return os.Rename(src, "/tmp/sbx-moved")
	})
	try("link out", true, func() error {
		src := filepath.Join(os.TempDir(), "sbxln")
		os.WriteFile(src, []byte("x"), 0o600)
		return os.Link(src, "/tmp/sbx-ln")
	})
	try("mkdir /opt", true, func() error {
		return os.Mkdir("/opt/sbx", 0o755)
	})
	try("connect tcp 9", true, func() error {
		c, e := net.DialTimeout("tcp", "127.0.0.1:9", 1e9)
		if e == nil {
			c.Close()
		}
		return e
	})
	try("bind tcp 9", true, func() error {
		l, e := net.Listen("tcp", "127.0.0.1:9")
		if e == nil {
			l.Close()
		}
		return e
	})
	try("udp non-allowed", true, func() error {
		c, e := net.Dial("udp", "127.0.0.1:9")
		if e == nil {
			_, e = c.Write([]byte("x"))
			c.Close()
		}
		return e
	})
	try("abstract unix", true, func() error {
		c, e := net.Dial("unix", "\x00sbx")
		if e == nil {
			c.Close()
		}
		return e
	})
	for _, d := range pol.RWDirs {
		dd := d
		try("write in "+d, false, func() error {
			return os.WriteFile(filepath.Join(dd, "sbx-probe"), []byte("x"), 0o600)
		})
	}
	try("read resolv.conf", false, func() error {
		_, e := os.ReadFile("/etc/resolv.conf")
		return e
	})
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	out := map[string]any{"abi": rep.ABI, "fs": rep.FS, "tcp": rep.TCP,
		"scoped": rep.Scoped, "mode": rep.Mode, "probes": probes}
	enc.Encode(out)
	bad := false
	for _, pr := range probes {
		if !pr.OK {
			bad = true
		}
	}
	if bad {
		return 1
	}
	return 0
}
