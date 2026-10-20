// SPDX-License-Identifier: 0BSD

package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func encManifest() *Manifest {
	return &Manifest{Version: 1,
		Enc: &EncInfo{V: 1, Alg: "xchacha20poly1305-siv-v1", KID: "0123456789abcdef"},
		Files: []File{
			{Path: "0123456789abcdef0123456789abcdef", Size: 10, Mode: 0o600,
				Chunks: []ChunkRef{{Hash: Hash{1}, Size: 10}}},
			{Path: "meta", Size: 3, Mode: 0o600, Inline: []byte("xyz")},
		}}
}

func TestEncValidate(t *testing.T) {
	good := encManifest()
	if err := good.Validate(DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		mut  func(*Manifest)
	}{
		{"bad-alg", func(m *Manifest) { m.Enc.Alg = "aes" }},
		{"bad-kid", func(m *Manifest) { m.Enc.KID = "zz" }},
		{"dirs", func(m *Manifest) { m.Dirs = []string{"x"} }},
		{"no-meta", func(m *Manifest) { m.Files = m.Files[:1] }},
		{"path-not-opaque", func(m *Manifest) { m.Files[0].Path = "x.dat" }},
		{"mode", func(m *Manifest) { m.Files[0].Mode = 0o644 }},
		{"mtime", func(m *Manifest) { m.Files[0].ModTimeNS = 1 }},
	}
	for _, c := range cases {
		m := encManifest()
		c.mut(m)
		if err := m.Validate(DefaultLimits()); err == nil {
			t.Fatalf("%s accepted", c.name)
		}
	}
}

func TestEncCanonical(t *testing.T) {
	m := encManifest()
	b1, _, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b2, _, err := m.Canonical()
	if err != nil || !bytes.Equal(b1, b2) {
		t.Fatal("not canonical")
	}
	if !strings.Contains(string(b1), `"enc"`) {
		t.Fatal("enc missing")
	}
	m2, err := DecodeManifest(bytes.NewReader(b1), 1<<20)
	if err != nil || m2.Enc == nil || m2.Enc.KID != m.Enc.KID {
		t.Fatal("decode")
	}
}

func FuzzDecodeManifestEnc(f *testing.F) {
	b, _ := json.Marshal(encManifest())
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := DecodeManifest(bytes.NewReader(data), 1<<20)
		if err == nil && m != nil {
			_ = m.Validate(DefaultLimits())
		}
	})
}
