// SPDX-License-Identifier: 0BSD

package icons

import (
	"bytes"
	"crypto/sha256"
	"image/png"
	"testing"
)

func TestIcons(t *testing.T) {
	var golden string
	for s := OK; s <= Offline; s++ {
		b := PNG(s, 32)
		img, err := png.Decode(bytes.NewReader(b))
		if err != nil || img.Bounds().Dx() != 32 {
			t.Fatalf("bad icon %d", s)
		}
		sum := sha256.Sum256(b)
		golden += string(sum[:])
	}
	if len(PNG(OK, 64)) == 0 || len(ICO(OK, 32)) <= 22 {
		t.Fatal("missing icons")
	}
	// determinism
	if !bytes.Equal(PNG(OK, 32), PNG(OK, 32)) {
		t.Fatal("not deterministic")
	}
}
