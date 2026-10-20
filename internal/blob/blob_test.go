// SPDX-License-Identifier: 0BSD

package blob_test

import (
	"strings"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/blob"
)

func TestValidKeyGrammar(t *testing.T) {
	if err := blob.ValidKey("u/abc-Def_9/m/" + strings.Repeat("0123456789abcdef", 4)); err != nil {
		t.Fatal(err)
	}
}

func FuzzValidKey(f *testing.F) {
	f.Add("u/u1/c/" + strings.Repeat("ab", 32))
	f.Add("u/../m/" + strings.Repeat("00", 32))
	f.Add("")
	f.Fuzz(func(t *testing.T, key string) {
		err := blob.ValidKey(key)
		if err != nil {
			return
		}
		parts := strings.Split(key, "/")
		if len(parts) != 4 || parts[0] != "u" || (parts[2] != "c" && parts[2] != "m") {
			t.Fatalf("accepted key %q violates grammar", key)
		}
		if strings.Contains(key, "..") || len(parts[3]) != 64 {
			t.Fatalf("accepted key %q violates grammar", key)
		}
	})
}
