// SPDX-License-Identifier: 0BSD

// Package bwlimit provides a byte token bucket and a bounded registry
// of per-key buckets for bandwidth throttling.
package bwlimit

import (
	"context"
	"sync"
	"time"
)

const (
	minBurst = 64 << 10
	maxKeys  = 65536
)

// Bucket is a byte token bucket. A zero rate passes everything.
type Bucket struct {
	mu    sync.Mutex
	rate  int64
	avail float64
	last  time.Time
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// New returns a bucket limited to bytesPerSec. now and sleep are
// injectable for tests.
func New(bytesPerSec int64, now func() time.Time, sleep func(context.Context, time.Duration) error) *Bucket {
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return &Bucket{rate: bytesPerSec, avail: burstFor(bytesPerSec), last: now(), now: now, sleep: sleep}
}

func burstFor(rate int64) float64 {
	if rate < 1 {
		return minBurst
	}
	b := float64(rate) / 2
	if b < minBurst {
		return minBurst
	}
	return b
}

// SetRate changes the limit; 0 disables throttling.
func (b *Bucket) SetRate(rate int64) {
	b.mu.Lock()
	b.refill(b.now())
	b.rate = rate
	b.avail = burstFor(rate)
	b.mu.Unlock()
}

func (b *Bucket) refill(t time.Time) {
	if b.rate <= 0 {
		return
	}
	b.avail += t.Sub(b.last).Seconds() * float64(b.rate)
	if m := burstFor(b.rate); b.avail > m {
		b.avail = m
	}
	b.last = t
}

// Wait blocks until n bytes may pass, splitting chunks larger than the
// burst so fairness is kept. Context cancel returns promptly.
func (b *Bucket) Wait(ctx context.Context, n int) error {
	b.mu.Lock()
	if b.rate <= 0 {
		b.mu.Unlock()
		return nil
	}
	need := n
	for need > 0 {
		b.refill(b.now())
		if b.avail > 0 {
			take := float64(need)
			if take > b.avail {
				take = b.avail
			}
			b.avail -= take
			need -= int(take)
			continue
		}
		chunk := float64(need)
		if m := burstFor(b.rate); chunk > m {
			chunk = m
		}
		d := time.Duration(chunk / float64(b.rate) * 1e9)
		b.mu.Unlock()
		if err := b.sleep(ctx, d); err != nil {
			return err
		}
		b.mu.Lock()
	}
	b.mu.Unlock()
	return nil
}

// Registry returns shared buckets per string key, bounded to 65536
// entries with oldest-idle eviction.
type Registry struct {
	mu    sync.Mutex
	m     map[string]*entry
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

type entry struct {
	b    *Bucket
	last time.Time
}

// NewRegistry returns a registry using injectable clock and sleep.
func NewRegistry(now func() time.Time, sleep func(context.Context, time.Duration) error) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{m: map[string]*entry{}, now: now, sleep: sleep}
}

// Get returns the shared bucket for key, creating it at rate.
func (r *Registry) Get(key string, rate int64) *Bucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.m[key]; ok {
		e.last = r.now()
		return e.b
	}
	if len(r.m) >= maxKeys {
		var oldest string
		var ot time.Time
		for k, e := range r.m {
			if oldest == "" || e.last.Before(ot) {
				oldest, ot = k, e.last
			}
		}
		delete(r.m, oldest)
	}
	b := New(rate, r.now, r.sleep)
	r.m[key] = &entry{b: b, last: r.now()}
	return b
}

// Evict removes keys idle for longer than d.
func (r *Registry) Evict(d time.Duration) {
	cut := r.now().Add(-d)
	r.mu.Lock()
	for k, e := range r.m {
		if e.last.Before(cut) {
			delete(r.m, k)
		}
	}
	r.mu.Unlock()
}

// Len reports the number of live buckets.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}
