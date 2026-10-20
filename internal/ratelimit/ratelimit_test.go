// SPDX-License-Identifier: 0BSD

package ratelimit

import (
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
)

func TestAllow(t *testing.T) {
	c := testclock.New(time.Now())
	l := New(10, 5, 100, c.NowFunc())
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("k", 1); !ok {
			t.Fatal("burst denied")
		}
	}
	ok, retry := l.Allow("k", 1)
	if ok || retry <= 0 {
		t.Fatal("should deny with retry")
	}
	c.Add(time.Second)
	if ok, _ := l.Allow("k", 1); !ok {
		t.Fatal("refill failed")
	}
	// Separate keys are independent.
	if ok, _ := l.Allow("other", 5); !ok {
		t.Fatal("other key denied")
	}
	// Eviction.
	l2 := New(1, 1, 2, c.NowFunc())
	l2.Allow("a", 0)
	l2.Allow("b", 0)
	l2.Allow("c", 0)
	if len(l2.items) != 2 {
		t.Fatal("eviction")
	}
}

func BenchmarkAllow(b *testing.B) {
	c := testclock.New(time.Now())
	l := New(1e9, 1e9, 1<<16, c.NowFunc())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Allow("key", 1)
	}
}

func BenchmarkAllowMultiKey(b *testing.B) {
	c := testclock.New(time.Now())
	l := New(1e9, 1e9, 1<<16, c.NowFunc())
	keys := make([]string, 4096)
	for i := range keys {
		keys[i] = string(rune(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Allow(keys[i%4096], 1)
	}
}
