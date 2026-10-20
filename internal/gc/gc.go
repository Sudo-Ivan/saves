// SPDX-License-Identifier: 0BSD

// Package gc runs the background reclamation jobs: pending snapshot
// expiry, zero-ref chunk and manifest deletion past the grace period,
// and deleted-user purges. All work runs under a lease so only one
// instance collects at a time and every step is crash safe.
package gc

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/meta"
)

// Options configures the collector.
type Options struct {
	Holder    string
	LeaseName string
	LeaseTTL  time.Duration
	Grace     time.Duration // zero-ref retention before deletion
	Interval  time.Duration
	BatchSize int
	Clock     func() time.Time
}

// Report summarizes one collection pass.
type Report struct {
	LeaseHeld        bool
	ExpiredPending   int
	ChunksDeleted    int
	ManifestsDeleted int
	UsersPurged      int
	Errors           int
}

// Collector runs the jobs.
type Collector struct {
	meta  meta.Store
	blob  blob.Store
	o     Options
	clock func() time.Time
}

// New builds a collector.
func New(m meta.Store, b blob.Store, o Options) *Collector {
	if o.Holder == "" {
		o.Holder = "gc"
	}
	if o.LeaseName == "" {
		o.LeaseName = "gc"
	}
	if o.LeaseTTL <= 0 {
		o.LeaseTTL = time.Minute
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 100
	}
	if o.Interval <= 0 {
		o.Interval = time.Minute
	}
	c := &Collector{meta: m, blob: b, o: o, clock: o.Clock}
	if c.clock == nil {
		c.clock = time.Now
	}
	return c
}

func (c *Collector) now() time.Time { return c.clock() }

// RunOnce performs one pass under the lease.
func (c *Collector) RunOnce(ctx context.Context) (Report, error) {
	var rep Report
	ok, err := c.meta.AcquireLease(ctx, c.o.LeaseName, c.o.Holder, c.o.LeaseTTL)
	if err != nil {
		return rep, err
	}
	if !ok {
		return rep, nil
	}
	rep.LeaseHeld = true
	grace := c.now().Add(-c.o.Grace)
	// Expire pending snapshots.
	n, err := c.meta.ExpirePending(ctx, c.now(), c.o.BatchSize)
	if err != nil {
		rep.Errors++
	} else {
		rep.ExpiredPending = n
	}
	// Zero-ref chunks past grace: mark deleting -> blob delete -> row.
	chunks, err := c.meta.UnreferencedChunks(ctx, grace, c.o.BatchSize)
	if err != nil {
		rep.Errors++
	}
	for _, ch := range chunks {
		if ctx.Err() != nil {
			break
		}
		marked, err := c.meta.MarkDeleting(ctx, ch.UserID, ch.Hash)
		if err != nil {
			rep.Errors++
			continue
		}
		if !marked {
			continue
		}
		if err := c.blob.Delete(ctx, blob.ChunkKey(ch.UserID, ch.Hash)); err != nil && !errors.Is(err, blob.ErrNotFound) {
			rep.Errors++
			continue // leave row in deleting; next pass or fsck heals
		}
		if _, err := c.meta.DeleteChunkRow(ctx, ch.UserID, ch.Hash); err != nil {
			rep.Errors++
			continue
		}
		rep.ChunksDeleted++
	}
	// Zero-ref manifests past grace.
	mfs, err := c.meta.UnreferencedManifests(ctx, grace, c.o.BatchSize)
	if err != nil {
		rep.Errors++
	}
	for _, mf := range mfs {
		if ctx.Err() != nil {
			break
		}
		if err := c.blob.Delete(ctx, blob.ManifestKey(mf.UserID, mf.Hash)); err != nil && !errors.Is(err, blob.ErrNotFound) {
			rep.Errors++
			continue
		}
		if ok, err := c.meta.DeleteManifestRow(ctx, mf.UserID, mf.Hash); err != nil || !ok {
			if err != nil {
				rep.Errors++
			}
			continue
		}
		rep.ManifestsDeleted++
	}
	// Purge soft-deleted users.
	pu, err := c.meta.PurgedUsers(ctx, c.o.BatchSize)
	if err != nil {
		rep.Errors++
	}
	for _, u := range pu {
		if ctx.Err() != nil {
			break
		}
		prefix := "u/" + u.ID + "/"
		var lastErr error
		lerr := c.blob.List(ctx, prefix, func(e blob.Entry) error {
			return c.blob.Delete(ctx, e.Key)
		})
		if lerr != nil && !errors.Is(lerr, blob.ErrNotFound) {
			lastErr = lerr
		}
		if lastErr != nil {
			rep.Errors++
			continue
		}
		if err := c.meta.FinishPurge(ctx, u.ID); err != nil {
			rep.Errors++
			continue
		}
		rep.UsersPurged++
	}
	return rep, nil
}

// Run loops RunOnce on the interval with jitter until ctx ends.
func (c *Collector) Run(ctx context.Context) error {
	for {
		if _, err := c.RunOnce(ctx); err != nil {
			// keep going; lease loss or transient db errors are normal
		}
		// #nosec G404 -- jitter does not need crypto randomness
		jitter := c.o.Interval/4 + time.Duration(rand.Int63n(int64(c.o.Interval/4)))
		t := time.NewTimer(jitter)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
