// SPDX-License-Identifier: 0BSD

package api

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidatePath(t *testing.T) {
	good := []string{
		"a", "a/b/c", "World Saves/level.dat", "x_y-z.dat",
		strings.Repeat("a/", 63) + "b",
	}
	for _, p := range good {
		if err := ValidatePath(p, 64); err != nil {
			t.Errorf("valid path %q rejected: %v", p, err)
		}
	}
	bad := []string{
		"", "/abs", "a/", "a//b", "a/./b", "../up", "a/../b",
		"a\\b", "a<b", "a:b", "a\"b", "a|b", "a?b", "a*b",
		"trail.", "trail ", "CON", "con.txt", "COM1", "lpt9.dat",
		strings.Repeat("a", 256),
		strings.Repeat("a/", 65) + "b",
		strings.Repeat("x", 1025),
		string([]byte{0xff, 0xfe}),
		"a\x00b", "a\x1fb",
	}
	for _, p := range bad {
		if err := ValidatePath(p, 64); err == nil {
			t.Errorf("invalid path %q accepted", p)
		}
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"a/b/c":      "a/b/c",
		"a\\b":       "a/b",
		"/a//b/./c/": "a/b/c",
		"../a":       "a",
		"a/../../b":  "b",
		"..":         "",
	}
	for in, want := range cases {
		if got := CleanPath(in); got != want {
			t.Errorf("CleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateAppID(t *testing.T) {
	for _, ok := range []string{"minecraft-java", "gog:1207658924", "a.b_c"} {
		if err := ValidateAppID(ok); err != nil {
			t.Errorf("app id %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "A", "-a", "a b", strings.Repeat("a", 65), "a/b"} {
		if err := ValidateAppID(bad); err == nil {
			t.Errorf("app id %q accepted", bad)
		}
	}
}

func TestValidateSlotName(t *testing.T) {
	for _, ok := range []string{"My World", "slot-1", "über"} {
		if err := ValidateSlotName(ok); err != nil {
			t.Errorf("slot %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a/b", "a\\b", "a\x00b", strings.Repeat("s", 129)} {
		if err := ValidateSlotName(bad); err == nil {
			t.Errorf("slot %q accepted", bad)
		}
	}
}

func TestParseHash(t *testing.T) {
	h, err := ParseHash(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if h.String() != strings.Repeat("ab", 32) {
		t.Fatal("round trip mismatch")
	}
	for _, bad := range []string{"", "zz" + strings.Repeat("0", 62), strings.Repeat("a", 63)} {
		if _, err := ParseHash(bad); err == nil {
			t.Errorf("hash %q accepted", bad)
		}
	}
}

func TestDecodeManifest(t *testing.T) {
	valid := `{"version":1,"files":[{"path":"a","size":0,"mode":420,"mtime_ns":1}]}`
	m, err := DecodeManifest(strings.NewReader(valid), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 1 || len(m.Files) != 1 {
		t.Fatal("decode mismatch")
	}
	for name, doc := range map[string]string{
		"dup key":       `{"version":1,"version":1,"files":[]}`,
		"unknown field": `{"version":1,"files":[],"bogus":1}`,
		"trailing":      `{"version":1,"files":[]} {"x":1}`,
		"trailing junk": `{"version":1,"files":[]}x`,
		"not an object": `42`,
	} {
		if _, err := DecodeManifest(strings.NewReader(doc), 1<<20); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := DecodeManifest(strings.NewReader(valid), 10); err == nil {
		t.Error("oversize manifest accepted")
	}
}

func TestManifestValidate(t *testing.T) {
	lim := DefaultLimits()
	mk := func(files ...File) *Manifest { return &Manifest{Version: 1, Files: files} }
	ch := ChunkRef{Hash: HashBytes([]byte("x")), Size: uint32(lim.MinChunkBytes)}
	good := []*Manifest{
		mk(),
		mk(File{Path: "a", Size: 0, Mode: 0o644}),
		mk(File{Path: "a/b", Size: 5, Inline: []byte("hello"), Mode: 0o644}),
		mk(File{Path: "a", Size: lim.MinChunkBytes + 10, Chunks: []ChunkRef{ch, {Hash: HashBytes([]byte("y")), Size: 10}}}),
		mk(File{Path: "a", Size: 1, Inline: []byte("x")}, File{Path: "b", Size: 0}),
	}
	for i, m := range good {
		if err := m.Validate(lim); err != nil {
			t.Errorf("good[%d] rejected: %v", i, err)
		}
	}
	bad := []*Manifest{
		{Version: 2},
		mk(File{Path: "b"}, File{Path: "a"}),
		mk(File{Path: "a"}, File{Path: "a"}),
		mk(File{Path: "A"}, File{Path: "a"}),
		mk(File{Path: "a"}, File{Path: "a/b"}),
		mk(File{Path: "a", Size: 5}),
		mk(File{Path: "a", Size: 5, Inline: []byte("xy")}),
		mk(File{Path: "a", Size: 1, Inline: []byte("x"), Chunks: []ChunkRef{{Size: 1}}}),
		mk(File{Path: "a", Size: lim.InlineMaxBytes + 1, Inline: bytes.Repeat([]byte("x"), int(lim.InlineMaxBytes)+1)}),
		mk(File{Path: "a", Size: 10, Chunks: []ChunkRef{{Size: 5}, {Size: 5}}}),
		mk(File{Path: "a", Size: 5, Chunks: []ChunkRef{{Size: 10}}}),
		{Version: 1, Dirs: []string{"a/../b"}},
		{Version: 1, Dirs: []string{"d"}, Files: []File{{Path: "d"}}},
	}
	for i, m := range bad {
		if err := m.Validate(lim); err == nil {
			t.Errorf("bad[%d] accepted", i)
		}
	}
}

func TestManifestCanonical(t *testing.T) {
	m := &Manifest{Version: 1, Files: []File{
		{Path: "b", Size: 0, Mode: 0o100644},
		{Path: "a", Size: 0},
	}}
	b1, h1, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	m2 := &Manifest{Version: 1, Files: []File{
		{Path: "a", Size: 0},
		{Path: "b", Size: 0, Mode: 0o100644},
	}}
	b2, h2, err := m2.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) || h1 != h2 {
		t.Error("canonical encoding not deterministic")
	}
	m3, err := DecodeManifest(bytes.NewReader(b1), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := m3.Validate(DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}

func FuzzValidatePath(f *testing.F) {
	f.Add("a/b/c")
	f.Add("../evil")
	f.Add("CON.txt")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidatePath(s, 64)
		_ = ValidatePath(s, 4)
	})
}

func FuzzDecodeManifest(f *testing.F) {
	f.Add(`{"version":1,"files":[]}`)
	f.Add(`{"version":1,"files":[{"path":"a","size":0,"mode":0,"mtime_ns":0}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		m, err := DecodeManifest(strings.NewReader(s), 1<<20)
		if err != nil {
			return
		}
		if _, _, err := m.Canonical(); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzManifestCanonicalRoundTrip(f *testing.F) {
	f.Add(`{"version":1,"files":[{"path":"a","size":1,"mode":420,"mtime_ns":5,"inline":"eA=="}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		m, err := DecodeManifest(strings.NewReader(s), 1<<20)
		if err != nil {
			return
		}
		b1, h1, err := m.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		m2, err := DecodeManifest(bytes.NewReader(b1), 1<<20)
		if err != nil {
			t.Fatalf("canonical bytes do not decode: %v", err)
		}
		_, h2, err := m2.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if h1 != h2 {
			t.Fatal("canonical hash not stable across round trip")
		}
	})
}

func FuzzValidateSlotName(f *testing.F) {
	f.Add("My World")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateSlotName(s)
	})
}
