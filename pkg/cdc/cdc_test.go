// SPDX-License-Identifier: 0BSD

package cdc

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand/v2"
	"testing"
)

func testParams() Params {
	return Params{Min: 2 << 10, Avg: 8 << 10, Max: 32 << 10}
}

func randomData(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func concat(chunks [][]byte) []byte {
	var out []byte
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func TestSplitConcat(t *testing.T) {
	p := testParams()
	for _, n := range []int{0, 1, 100, p.Min - 1, p.Min, p.Min + 1, p.Avg, p.Max, p.Max + 1, 5 * p.Max} {
		data := randomData(n)
		chunks := Chunks(p, data)
		if !bytes.Equal(concat(chunks), data) {
			t.Fatalf("n=%d: chunks do not reassemble", n)
		}
		for i, c := range chunks {
			if i < len(chunks)-1 && (len(c) < p.Min || len(c) > p.Max) {
				t.Fatalf("n=%d: chunk %d size %d out of bounds", n, i, len(c))
			}
			if len(c) > p.Max {
				t.Fatalf("n=%d: chunk %d exceeds max", n, i)
			}
		}
	}
}

func TestSplitDeterministic(t *testing.T) {
	p := testParams()
	data := randomData(256 << 10)
	a := Chunks(p, data)
	b := Chunks(p, data)
	if len(a) != len(b) {
		t.Fatal("chunk count differs")
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			t.Fatalf("chunk %d differs", i)
		}
	}
}

func TestBoundaryShiftResilience(t *testing.T) {
	p := testParams()
	for trial := 0; trial < 20; trial++ {
		data := randomData(512 << 10)
		mut := bytes.Clone(data)
		// Insert one byte near the start.
		pos := p.Max + mrand.IntN(p.Max)
		mut = append(mut[:pos], append([]byte{0xAB}, mut[pos:]...)...)
		a := Chunks(p, data)
		b := Chunks(p, mut)
		sa := make(map[string]struct{}, len(a))
		for _, c := range a {
			sa[string(c)] = struct{}{}
		}
		var same int
		for _, c := range b {
			if _, ok := sa[string(c)]; ok {
				same++
			}
		}
		if float64(same) < 0.9*float64(len(b)) {
			t.Fatalf("trial %d: only %d/%d chunks identical after 1 byte insert", trial, same, len(b))
		}
	}
}

func TestStreamingEqualsInMemory(t *testing.T) {
	p := DefaultParams()
	data := randomData(6 << 20)
	want := concat(Chunks(p, data))
	for _, readSize := range []int{1, 7, 4096, 1 << 20} {
		r := &slowReader{r: bytes.NewReader(data), n: readSize}
		ck, err := NewChunker(r, p)
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		var count int
		err = ck.Each(func(c []byte) error {
			count++
			got = append(got, c...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("readSize=%d: stream output differs", readSize)
		}
		mem := Chunks(p, data)
		if count != len(mem) {
			t.Fatalf("readSize=%d: %d chunks, want %d", readSize, count, len(mem))
		}
	}
	// Boundaries must match too, not just the bytes.
	r := bytes.NewReader(data)
	ck, _ := NewChunker(r, p)
	var sizes []int
	_ = ck.Each(func(c []byte) error {
		sizes = append(sizes, len(c))
		return nil
	})
	for i, c := range Chunks(p, data) {
		if sizes[i] != len(c) {
			t.Fatalf("chunk %d size %d, want %d", i, sizes[i], len(c))
		}
	}
}

// slowReader caps each Read at n bytes.
type slowReader struct {
	r io.Reader
	n int
}

func (s *slowReader) Read(p []byte) (int, error) {
	if len(p) > s.n {
		p = p[:s.n]
	}
	return s.r.Read(p)
}

func TestParamsValidate(t *testing.T) {
	if err := DefaultParams().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Params{
		{Min: 0, Avg: 8, Max: 32},
		{Min: 4, Avg: 7, Max: 32},
		{Min: 4, Avg: 64, Max: 32},
		{Min: 4, Avg: 8, Max: 1 << 30},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("params %+v accepted", p)
		}
	}
}

func FuzzCDCSplit(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add(randomData(8192))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := Params{Min: 1 << 10, Avg: 4 << 10, Max: 16 << 10}
		out := concat(Chunks(p, data))
		if !bytes.Equal(out, data) {
			t.Fatal("chunks do not reassemble")
		}
	})
}

func FuzzCDCStreamingEqualsInMemory(f *testing.F) {
	f.Add(randomData(65536), 3)
	f.Fuzz(func(t *testing.T, data []byte, readSize int) {
		if readSize < 1 {
			readSize = 1
		}
		p := Params{Min: 1 << 10, Avg: 4 << 10, Max: 16 << 10}
		want := Chunks(p, data)
		ck, err := NewChunker(&slowReader{r: bytes.NewReader(data), n: readSize}, p)
		if err != nil {
			t.Fatal(err)
		}
		var got [][]byte
		_ = ck.Each(func(c []byte) error {
			got = append(got, bytes.Clone(c))
			return nil
		})
		if len(got) != len(want) {
			t.Fatalf("chunk count %d, want %d", len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("chunk %d differs", i)
			}
		}
	})
}

func BenchmarkSplit(b *testing.B) {
	p := DefaultParams()
	data := randomData(64 << 20)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		n = 0
		Split(p, data, func(c []byte) bool {
			n += len(c)
			return true
		})
	}
	_ = n
}

func BenchmarkChunker(b *testing.B) {
	p := DefaultParams()
	data := randomData(64 << 20)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ck, _ := NewChunker(bytes.NewReader(data), p)
		_ = ck.Each(func(c []byte) error { return nil })
	}
}
