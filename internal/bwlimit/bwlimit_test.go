// SPDX-License-Identifier: 0BSD

package bwlimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fake struct {
	mu    sync.Mutex
	now   time.Time
	slept time.Duration
}

func (f *fake) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}
func (f *fake) sleep(ctx context.Context, d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slept += d
	f.now = f.now.Add(d)
	return nil
}
func (f *fake) total() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.slept
}
func (f *fake) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func TestBucketRate(t *testing.T) {
	f := &fake{now: time.Now()}
	b := New(1000, f.clock, f.sleep)
	for i := 0; i < 66; i++ {
		if err := b.Wait(context.Background(), 1000); err != nil {
			t.Fatal(err)
		}
	}
	start := f.total()
	if err := b.Wait(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	got := f.total() - start
	if got < 500*time.Millisecond || got > 1100*time.Millisecond {
		t.Fatalf("slept=%v", got)
	}
}

func TestBucketBurstAndSplit(t *testing.T) {
	f := &fake{now: time.Now()}
	b := New(100, f.clock, f.sleep) // burst floor is 64 KiB
	if err := b.Wait(context.Background(), 200<<10); err != nil {
		t.Fatal(err)
	}
	if f.total() <= 0 {
		t.Fatal("should have waited")
	}
}

func TestBucketZeroAndSetRate(t *testing.T) {
	f := &fake{now: time.Now()}
	b := New(0, f.clock, f.sleep)
	if err := b.Wait(context.Background(), 1<<20); err != nil {
		t.Fatal(err)
	}
	if f.total() != 0 {
		t.Fatal("rate 0 should pass")
	}
	b.SetRate(100)
	if err := b.Wait(context.Background(), 200<<10); err != nil {
		t.Fatal(err)
	}
	if f.total() <= 0 {
		t.Fatal("no throttle after SetRate")
	}
}

func TestBucketCancel(t *testing.T) {
	f := &fake{now: time.Now()}
	sleep := func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	b := New(10, f.clock, sleep)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Wait(ctx, 100<<10); err == nil {
		t.Fatal("want cancel")
	}
}

func TestBucketConcurrent(t *testing.T) {
	f := &fake{now: time.Now()}
	var mu atomic.Int64
	sleep := func(ctx context.Context, d time.Duration) error {
		mu.Add(int64(d))
		f.advance(d)
		return nil
	}
	b := New(1000, f.clock, sleep)
	done := make(chan bool, 4)
	for i := 0; i < 4; i++ {
		go func() { _ = b.Wait(context.Background(), 70<<10); done <- true }()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	if mu.Load() <= 0 {
		t.Fatal("no waiting")
	}
}

func TestRegistry(t *testing.T) {
	f := &fake{now: time.Now()}
	r := NewRegistry(f.clock, f.sleep)
	b1 := r.Get("a", 100)
	b2 := r.Get("a", 100)
	if b1 != b2 {
		t.Fatal("not shared")
	}
	if r.Get("b", 100) == b1 {
		t.Fatal("collision")
	}
	r.Evict(time.Second)
	if r.Len() != 2 {
		t.Fatal("evicted too early")
	}
	f.advance(2 * time.Second)
	r.Evict(time.Second)
	if r.Len() != 0 {
		t.Fatal("not evicted")
	}
}
