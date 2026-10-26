// SPDX-License-Identifier: 0BSD

// Package ratelimit is a bounded in-memory token bucket keyed by string
// with injected time and LRU eviction.
package ratelimit

import (
	"container/list"
	"sync"
	"time"
)

// Limiter is a keyed token bucket.
type Limiter struct {
	mu      sync.Mutex
	clock   func() time.Time
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	ll      *list.List
	items   map[string]*list.Element
}

type entry struct {
	key    string
	tokens float64
	last   time.Time
}

// New returns a limiter allowing rate tokens/sec with a burst cap,
// tracking at most maxKeys buckets before evicting least recently used.
func New(rate, burst float64, maxKeys int, clock func() time.Time) *Limiter {
	if maxKeys <= 0 {
		maxKeys = 1 << 16
	}
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{clock: clock, rate: rate, burst: burst, maxKeys: maxKeys, ll: list.New(), items: map[string]*list.Element{}}
}

// Allow consumes cost tokens for key. It reports whether the call is
// allowed and, when not, the suggested retry-after duration.
func (l *Limiter) Allow(key string, cost float64) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	var e *entry
	if el, ok := l.items[key]; ok {
		e = el.Value.(*entry)
		l.ll.MoveToFront(el)
	} else {
		if len(l.items) >= l.maxKeys {
			back := l.ll.Back()
			delete(l.items, back.Value.(*entry).key)
			l.ll.Remove(back)
		}
		e = &entry{key: key, tokens: l.burst}
		l.items[key] = l.ll.PushFront(e)
	}
	e.tokens += (now.Sub(e.last).Seconds()) * l.rate
	if e.tokens > l.burst {
		e.tokens = l.burst
	}
	e.last = now
	if e.tokens >= cost {
		e.tokens -= cost
		return true, 0
	}
	need := (cost - e.tokens) / l.rate
	return false, time.Duration(need * float64(time.Second))
}

// Clear removes the bucket for key.
func (l *Limiter) Clear(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		delete(l.items, key)
		l.ll.Remove(el)
	}
}
