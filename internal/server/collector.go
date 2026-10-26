// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

// MinutePoint is one minute of live traffic for sparklines.
type MinutePoint struct {
	At                time.Time
	Requests, Errors  int64
	BytesIn, BytesOut int64
}

// Collector holds cheap in-memory counters flushed to stats_daily.
type Collector struct {
	mu       sync.Mutex
	now      func() time.Time
	store    meta.Store
	day      int
	req      int64
	err5xx   int64
	bin      int64
	bout     int64
	sign     int64
	okL      int64
	failL    int64
	snap     int64
	act      map[string]bool
	ring     [60]MinutePoint
	ringI    int
	stop     chan struct{}
	done     chan struct{}
	drops    uint64
	interval time.Duration
}

// NewCollector returns a collector; store may be nil.
func NewCollector(store meta.Store, now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	return &Collector{store: store, now: now, act: map[string]bool{},
		day: meta.BandwidthDay(now()), interval: 30 * time.Second,
		stop: make(chan struct{}), done: make(chan struct{})}
}

// Count records one request event. All O(1).
func (c *Collector) Count(status, bin, bout int64) {
	c.mu.Lock()
	c.req++
	c.bin += bin
	c.bout += bout
	if status >= 500 {
		c.err5xx++
	}
	mn := c.now().Truncate(time.Minute)
	same := c.ring[c.ringI%60].At.Equal(mn)
	if !same {
		c.ringI = (c.ringI + 1) % 60
		c.ring[c.ringI] = MinutePoint{At: mn}
	}
	r := &c.ring[c.ringI]
	r.Requests++
	r.BytesIn += bin
	r.BytesOut += bout
	if status >= 500 {
		r.Errors++
	}
	c.mu.Unlock()
}

// Signup records a registration.
func (c *Collector) Signup() { c.mu.Lock(); c.sign++; c.mu.Unlock() }

// Login records a web login outcome.
func (c *Collector) Login(ok bool) {
	c.mu.Lock()
	if ok {
		c.okL++
	} else {
		c.failL++
	}
	c.mu.Unlock()
}

// Snapshot records one committed snapshot.
func (c *Collector) Snapshot() { c.mu.Lock(); c.snap++; c.mu.Unlock() }

// Active marks uid active today, deduped.
func (c *Collector) Active(uid string) {
	c.mu.Lock()
	c.act[uid] = true
	c.mu.Unlock()
}

// Flush writes deltas and gauges; repeated flushes do not double count.
func (c *Collector) Flush(ctx context.Context) {
	if c.store == nil {
		return
	}
	c.mu.Lock()
	if meta.BandwidthDay(c.now()) != c.day {
		c.day = meta.BandwidthDay(c.now())
		c.act = map[string]bool{}
	}
	d := meta.StatsDelta{Day: c.day, Signups: c.sign, LoginsOK: c.okL,
		LoginsFailed: c.failL, Requests: c.req, Errors5xx: c.err5xx,
		BytesIn: c.bin, BytesOut: c.bout, Snapshots: c.snap}
	c.req, c.err5xx, c.bin, c.bout, c.sign, c.okL, c.failL, c.snap = 0, 0, 0, 0, 0, 0, 0, 0
	var uds []meta.UserDay
	for uid := range c.act {
		uds = append(uds, meta.UserDay{UserID: uid, Day: c.day})
	}
	c.act = map[string]bool{}
	c.mu.Unlock()
	_ = c.store.AddStats(ctx, []meta.StatsDelta{d})
	if len(uds) > 0 {
		_ = c.store.TouchActivity(ctx, uds)
	}
	t, _ := c.store.AdminTotals(ctx)
	_ = c.store.SetStatsGauges(ctx, c.day, t.UsedBytes, t.Users, int64(len(uds)))
}

// Live returns the last 60 minute buckets.
// Drops reports dropped flush events.
func (c *Collector) Drops() uint64 { c.mu.Lock(); defer c.mu.Unlock(); return c.drops }

func (c *Collector) Live() []MinutePoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]MinutePoint, 0, 60)
	for i := 0; i < 60; i++ {
		p := c.ring[(c.ringI+60-i)%60]
		if p.At.IsZero() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Start runs the flush loop.
func (c *Collector) Start() { go c.loop() }

func (c *Collector) loop() {
	defer close(c.done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.Flush(context.Background())
		case <-c.stop:
			return
		}
	}
}

// Close flushes and stops.
func (c *Collector) Close(ctx context.Context) {
	close(c.stop)
	<-c.done
	c.Flush(ctx)
}

// Dashboard aggregates admin metrics for the UI.
type Dashboard struct {
	Totals      meta.AdminTotals
	Series      []meta.StatsRow
	Live        []MinutePoint
	TopUsers    []meta.AdminUserRow
	TopApps     []meta.AppBytes
	LockedUsers int
	IPBlocks    int
	Pending     int64
	Banned      int64
	RecentAudit []meta.AuditEvent
	Overrides   int
}

// AdminDashboard builds the dashboard snapshot.
func (s *Server) AdminDashboard(ctx context.Context) Dashboard {
	var d Dashboard
	now := s.now()
	d.Totals, _ = s.Meta.AdminTotals(ctx)
	d.Pending = d.Totals.PendingUsers
	d.Banned = d.Totals.Banned
	to := meta.BandwidthDay(now)
	from := meta.BandwidthDay(now.AddDate(0, 0, -29))
	d.Series, _ = s.Meta.StatsSeries(ctx, from, to)
	if s.collector != nil {
		d.Live = s.collector.Live()
	}
	d.TopUsers, _ = s.Meta.TopUsersByStorage(ctx, 10)
	d.TopApps, _ = s.Meta.TopApps(ctx, 10)
	d.LockedUsers = len(s.web.userLock.Locked())
	blocks, _ := s.Meta.ListIPBlocks(ctx)
	d.IPBlocks = len(blocks)
	d.RecentAudit, _, _ = s.Meta.ListAudit(ctx, meta.AuditFilter{}, "", 15)
	return d
}
