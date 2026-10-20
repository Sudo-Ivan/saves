// SPDX-License-Identifier: 0BSD

// Package testclock is a manually advanced clock for deterministic tests.
package testclock

import (
	"sync"
	"time"
)

// Clock is a settable time source.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// New returns a clock set to t, or a fixed epoch when t is zero.
func New(t time.Time) *Clock {
	if t.IsZero() {
		t = time.Unix(1_700_000_000, 0)
	}
	return &Clock{now: t}
}

// Now returns the current fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// NowFunc returns c.Now as a meta.Options.Clock func.
func (c *Clock) NowFunc() func() time.Time { return c.Now }

// Add advances the clock.
func (c *Clock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
