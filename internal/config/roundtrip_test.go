// SPDX-License-Identifier: 0BSD

package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDurationZeroRoundTrip(t *testing.T) {
	var d Duration
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"0s"` {
		t.Fatalf("got %s", b)
	}
	var back Duration
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("marshal output %s failed to parse", b)
	}
}

func FuzzDurationRoundTrip(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(600e9))
	f.Add(int64(86400e9))
	f.Fuzz(func(t *testing.T, n int64) {
		d := Duration(n)
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var back Duration
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("marshal %s unparseable: %v", b, err)
		}
	})
}

func FuzzSizeRoundTrip(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(1 << 20))
	f.Add(int64(50 << 30))
	f.Fuzz(func(t *testing.T, n int64) {
		s := Size(n)
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var back Size
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("marshal %s unparseable: %v", b, err)
		}
	})
}

// The whole Defaults tree must marshal and re-validate.
func TestDefaultsRoundTrip(t *testing.T) {
	c := Defaults()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	f := t.TempDir() + "/cfg.json"
	writeFileHelper(t, f, b)
	if _, err := Load(f); err != nil {
		t.Fatalf("re-load of marshaled Defaults: %v", err)
	}
}

func writeFileHelper(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
