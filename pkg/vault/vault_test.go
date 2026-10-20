// SPDX-License-Identifier: 0BSD

package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"sync"
	"testing"
)

func TestVectors(t *testing.T) {
	var k Key
	copy(k[:], []byte("vault-vector-key-32bytes-123456789"))
	v := New(k)
	type vec struct {
		Path   string
		PathID string
		Plain  string
		CT     string
	}
	d, err := os.ReadFile("testdata/vectors.json")
	if err == nil {
		var vv struct {
			KID  string `json:"kid"`
			Vecs []vec  `json:"vectors"`
		}
		json.Unmarshal(d, &vv)
		if vv.KID != v.KID() {
			t.Fatalf("kid drift: %s vs %s", v.KID(), vv.KID)
		}
		for _, e := range vv.Vecs {
			if got := v.PathID(e.Path); got != e.PathID {
				t.Fatalf("PathID(%q) drift", e.Path)
			}
			ct := v.SealChunk([]byte(e.Plain))
			got := hex2(ct)
			if got != e.CT {
				t.Fatalf("SealChunk(%q) drift", e.Plain)
			}
		}
		return
	}
	// Generate the golden file once.
	var vv struct {
		KID  string `json:"kid"`
		Vecs []vec  `json:"vectors"`
	}
	vv.KID = v.KID()
	for _, p := range []string{"save/f", "a.dat", ""} {
		ct := v.SealChunk([]byte(p))
		vv.Vecs = append(vv.Vecs, vec{Path: p, PathID: v.PathID(p), Plain: p, CT: hex2(ct)})
	}
	b, _ := json.MarshalIndent(vv, "", "  ")
	os.MkdirAll("testdata", 0o755)
	os.WriteFile("testdata/vectors.json", b, 0o644)
	t.Fatal("wrote testdata/vectors.json; re-run")
}

func hex2(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, h[c>>4], h[c&15])
	}
	return string(out)
}

func TestDeterminism(t *testing.T) {
	v := New(Key{1})
	a := v.SealChunk([]byte("x"))
	b := v.SealChunk([]byte("x"))
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	v2 := New(Key{2})
	if bytes.Equal(v2.SealChunk([]byte("x")), a) {
		t.Fatal("different key same ct")
	}
	p, err := v.OpenChunk(a)
	if err != nil || string(p) != "x" {
		t.Fatal("open failed")
	}
}

func TestTamper(t *testing.T) {
	v := New(Key{9})
	ct := v.SealChunk([]byte("small"))
	for i := 0; i < len(ct); i++ {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x80
		if _, err := v.OpenChunk(bad); err == nil {
			t.Fatalf("accepted tamper at byte %d", i)
		}
	}
	if _, err := v.OpenChunk(ct[:len(ct)-1]); err == nil {
		t.Fatal("accepted truncate")
	}
	if _, err := v.OpenChunk(append(append([]byte(nil), ct...), 0)); err == nil {
		t.Fatal("accepted extension")
	}
	// swap nonce from another ct
	ct2 := v.SealChunk([]byte("other"))
	bad := append(append([]byte(nil), ct2[:24]...), ct[24:]...)
	if _, err := v.OpenChunk(bad); err == nil {
		t.Fatal("accepted swapped nonce")
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	v, rec, hdr, err := Create("pass", LightKDF)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(hdr, "wrong"); err != ErrBadPassphrase {
		t.Fatalf("want ErrBadPassphrase got %v", err)
	}
	v2, err := Unlock(hdr, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if v2.KID() != v.KID() {
		t.Fatal("kid mismatch")
	}
	v3, err := UnlockRecovery(hdr, rec)
	if err != nil {
		t.Fatal(err)
	}
	if v3.KID() != v.KID() {
		t.Fatal("recovery kid mismatch")
	}
	// change passphrase invalidates old
	hdr2, err := ChangePassphrase(hdr, "pass", "new", LightKDF)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(hdr2, "pass"); err != ErrBadPassphrase {
		t.Fatal("old passphrase still valid")
	}
	if _, err := Unlock(hdr2, "new"); err != nil {
		t.Fatal(err)
	}
	// tamper header
	for i := 0; i < len(hdr) && i < 60; i++ {
		bad := append([]byte(nil), hdr...)
		bad[i] = 'X'
		if _, err := Unlock(bad, "pass"); err == nil {
			t.Fatalf("accepted tampered header at %d", i)
		}
	}
	// new recovery
	rec2, hdr3, err := NewRecovery(hdr2, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnlockRecovery(hdr3, rec2); err != nil {
		t.Fatal(err)
	}
	if _, err := UnlockRecovery(hdr3, rec); err == nil {
		t.Fatal("old recovery still valid")
	}
}

func TestNonceUniqueness(t *testing.T) {
	v := New(Key{3})
	seen := map[string]bool{}
	buf := make([]byte, 16)
	for i := 0; i < 100000; i++ {
		rand.Read(buf)
		ct := v.SealChunk(buf)
		n := string(ct[:24])
		if seen[n] {
			t.Fatal("nonce reuse")
		}
		seen[n] = true
	}
}

func TestConcurrent(t *testing.T) {
	v := New(Key{4})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			buf := []byte{byte(i)}
			ct := v.SealChunk(buf)
			if _, err := v.OpenChunk(ct); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}

func FuzzOpenChunk(f *testing.F) {
	v := New(Key{5})
	f.Add([]byte("x"))
	f.Fuzz(func(t *testing.T, ct []byte) {
		out, err := v.OpenChunk(ct)
		if err != nil {
			return
		}
		if len(out) == 0 && len(ct) < 40 {
			t.Fatal("accepted invalid")
		}
	})
}

func FuzzUnlockHeader(f *testing.F) {
	f.Add([]byte(`{"v":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Unlock(b, "x")
	})
}

func FuzzParseRecovery(f *testing.F) {
	f.Add("AAAA-BBBB")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseRecovery(s)
	})
}

func FuzzSealOpenRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Fuzz(func(t *testing.T, p []byte) {
		v := New(Key{6})
		ct := v.SealChunk(p)
		out, err := v.OpenChunk(ct)
		if err != nil || !bytes.Equal(out, p) {
			t.Fatal("roundtrip failed")
		}
	})
}

func BenchmarkSealChunk(b *testing.B) {
	v := New(Key{7})
	for _, n := range []int{512 << 10, 2 << 20} {
		p := make([]byte, n)
		rand.Read(p)
		b.Run(bytes.NewBufferString("").String(), func(b *testing.B) {})
		b.Run(itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for i := 0; i < b.N; i++ {
				v.SealChunk(p)
			}
		})
	}
}

func BenchmarkOpenChunk(b *testing.B) {
	v := New(Key{7})
	for _, n := range []int{512 << 10, 2 << 20} {
		p := make([]byte, n)
		rand.Read(p)
		ct := v.SealChunk(p)
		b.Run(itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for i := 0; i < b.N; i++ {
				v.OpenChunk(ct)
			}
		})
	}
}

func itoa(n int) string {
	if n >= 1<<20 {
		return "2MiB"
	}
	return "512KiB"
}
