// SPDX-License-Identifier: 0BSD

package detect

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"testing"
)

// mkNBT builds a minimal level.dat payload.
func mkNBT() []byte {
	var b bytes.Buffer
	wstr := func(s string) { binary.Write(&b, binary.BigEndian, int16(len(s))); b.WriteString(s) }
	b.WriteByte(10) // compound
	wstr("")
	b.WriteByte(10)
	wstr("Data")
	b.WriteByte(8)
	wstr("LevelName")
	wstr("My World")
	b.WriteByte(4)
	wstr("LastPlayed")
	binary.Write(&b, binary.BigEndian, int64(1700000000000))
	b.WriteByte(0) // end Data
	b.WriteByte(0) // end root
	var gz bytes.Buffer
	g := gzip.NewWriter(&gz)
	g.Write(b.Bytes())
	g.Close()
	return gz.Bytes()
}

func TestNBT(t *testing.T) {
	l, err := ParseLevelDat(mkNBT())
	if err != nil {
		t.Fatal(err)
	}
	if l.Name != "My World" || l.LastPlayed.UnixMilli() != 1700000000000 {
		t.Fatalf("%+v", l)
	}
}

func FuzzNBT(f *testing.F) {
	f.Add(mkNBT())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = ParseLevelDat(b)
	})
}
