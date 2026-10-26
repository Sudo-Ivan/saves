// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"fmt"
	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/bwlimit"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// bwManager owns per-user and global bandwidth buckets, in-memory
// usage counters and the periodic flush to meta. It is nil when
// cfg.Bandwidth.Enabled is false: no wrappers, no accounting.
type bwManager struct {
	meta     meta.Store
	met      metricsAPI
	gUp      *bwlimit.Bucket
	gDown    *bwlimit.Bucket
	up, down func(uid string, rate int64) *bwlimit.Bucket
	clock    func() time.Time
	interval time.Duration
	stop     chan struct{}
	done     chan struct{}
	started  bool

	mu     sync.Mutex
	usage  map[string]*bwCounter
	deltas map[string]bwDelta
}

type bwCounter struct {
	dayKey, monthKey int
	up, down         int64
	mUp, mDown       int64
	loaded           bool
	lastStoreLoad    time.Time
}

type bwDelta struct{ up, down int64 }

type metricsAPI interface {
	BandwidthBytes(direction string, n int64)
	BandwidthThrottle(d time.Duration)
	BandwidthReject()
}

func newBwManager(m meta.Store, clock func() time.Time) *bwManager {
	upReg := bwlimit.NewRegistry(clock, nil)
	downReg := bwlimit.NewRegistry(clock, nil)
	return &bwManager{
		meta: m, clock: clock, interval: 30 * time.Second,
		up:   func(uid string, rate int64) *bwlimit.Bucket { return upReg.Get(uid+":u", rate) },
		down: func(uid string, rate int64) *bwlimit.Bucket { return downReg.Get(uid+":d", rate) },
		gUp:  bwlimit.New(0, clock, nil), gDown: bwlimit.New(0, clock, nil),
		stop: make(chan struct{}), done: make(chan struct{}),
		usage: map[string]*bwCounter{}, deltas: map[string]bwDelta{},
	}
}

func (b *bwManager) now() time.Time {
	if b.clock != nil {
		return b.clock()
	}
	return time.Now()
}

// start launches the flush and sweep goroutine.
func (b *bwManager) start() {
	b.started = true
	go b.loop()
}

// Close flushes the last deltas and stops the goroutine.
func (b *bwManager) Close() {
	if b.started {
		close(b.stop)
		<-b.done
	}
	b.flush()
}

func (b *bwManager) loop() {
	defer close(b.done)
	t := time.NewTicker(b.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			b.flush()
		case <-b.stop:
			return
		}
	}
}

func dayKey(t time.Time) int { return meta.BandwidthDay(t) }
func monthKey(t time.Time) int {
	t = t.UTC()
	return t.Year()*100 + int(t.Month())
}

// counter returns the user's in-memory counters, lazily loading this
// month's usage from the store on first touch and refreshing every
// 30s so multi-node deployments converge (soft caps).
func (b *bwManager) counter(ctx context.Context, uid string) *bwCounter {
	now := b.now()
	b.mu.Lock()
	c := b.usage[uid]
	if c == nil {
		c = &bwCounter{}
		b.usage[uid] = c
	}
	b.mu.Unlock()
	if !c.loaded || now.Sub(c.lastStoreLoad) > 30*time.Second {
		rows, err := b.meta.BandwidthUsage(ctx, uid,
			bwDayStart(now), dayKey(now))
		if err == nil {
			mk, dk := monthKey(now), dayKey(now)
			var up, down, mup, mdown int64
			for _, r := range rows {
				mup += r.Up
				mdown += r.Down
				if r.Day == dk {
					up, down = r.Up, r.Down
				}
			}
			b.mu.Lock()
			d := b.deltas[uid]
			c.dayKey = dk
			c.monthKey = mk
			c.up, c.down = up+d.up, down+d.down
			c.mUp, c.mDown = mup+d.up, mdown+d.down
			c.loaded = true
			c.lastStoreLoad = now
			b.mu.Unlock()
		}
	}
	return c
}

// bwDayStart returns the day key of the first of the UTC month.
func bwDayStart(t time.Time) int {
	t = t.UTC()
	return meta.BandwidthDay(time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC))
}

// add records bytes moved and queues a flush delta.
func (b *bwManager) add(uid string, up, down int64) {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.usage[uid]
	if c == nil {
		c = &bwCounter{loaded: true}
		b.usage[uid] = c
	}
	dk, mk := dayKey(now), monthKey(now)
	if c.dayKey != dk {
		c.up, c.down = 0, 0
		c.dayKey = dk
	}
	if c.monthKey != mk {
		c.mUp, c.mDown = 0, 0
		c.monthKey = mk
	}
	c.up += up
	c.down += down
	c.mUp += up
	c.mDown += down
	d := b.deltas[uid]
	d.up += up
	d.down += down
	b.deltas[uid] = d
}

func (b *bwManager) flush() {
	b.mu.Lock()
	deltas := b.deltas
	b.deltas = map[string]bwDelta{}
	b.mu.Unlock()
	if len(deltas) == 0 {
		return
	}
	rows := make([]meta.BandwidthRow, 0, len(deltas))
	for uid, d := range deltas {
		if d.up == 0 && d.down == 0 {
			continue
		}
		rows = append(rows, meta.BandwidthRow{
			UserID: uid, Day: dayKey(b.now()), Up: d.up, Down: d.down})
	}
	_ = b.meta.AddBandwidth(context.Background(), rows)
}

// capResult describes which period cap tripped, if any.
type capResult int

const (
	capNone capResult = iota
	capDaily
	capMonthly
)

// check returns the tripped cap for this user, considering the
// already-recorded period totals plus this request's declared size.
func (b *bwManager) check(ctx context.Context, uid string, pol policy, uploadSize int64) (capResult, bool) {
	if pol.daily == 0 && pol.monthly == 0 {
		return capNone, false
	}
	c := b.counter(ctx, uid)
	total := c.up + c.down + uploadSize
	mTotal := c.mUp + c.mDown + uploadSize
	if pol.daily > 0 && total >= pol.daily {
		return capDaily, true
	}
	if pol.monthly > 0 && mTotal >= pol.monthly {
		return capMonthly, true
	}
	return capNone, false
}

// policy is the resolved per-tier bandwidth policy.
type policy struct{ upBps, downBps, daily, monthly int64 }

// Snapshot returns the numbers /v1/me and the web page reuse.
func (b *bwManager) Snapshot(ctx context.Context, uid string, pol policy) map[string]any {
	if b == nil {
		return map[string]any{"enabled": false}
	}
	c := b.counter(ctx, uid)
	now := b.now().UTC()
	dailyReset := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	monthReset := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	return map[string]any{
		"enabled":                true,
		"upload_bytes_per_sec":   pol.upBps,
		"download_bytes_per_sec": pol.downBps,
		"daily_bytes":            pol.daily,
		"monthly_bytes":          pol.monthly,
		"today":                  map[string]any{"up": c.up, "down": c.down},
		"month":                  map[string]any{"up": c.mUp, "down": c.mDown},
		"resets": map[string]any{
			"daily_at":   dailyReset.Format(time.RFC3339),
			"monthly_at": monthReset.Format(time.RFC3339),
		},
	}
}

// Series returns zero-filled per-day up and down rows for the last
// days days, today's unflushed counters included.
func (b *bwManager) Series(ctx context.Context, uid string, days int) ([]meta.BandwidthRow, error) {
	if b == nil || days < 1 {
		return nil, nil
	}
	if days > 90 {
		days = 90
	}
	now := b.now().UTC()
	start := now.Truncate(24*time.Hour).AddDate(0, 0, -days+1)
	rows, err := b.meta.BandwidthUsage(ctx, uid, meta.BandwidthDay(start), meta.BandwidthDay(now))
	if err != nil {
		return nil, err
	}
	byDay := map[int]meta.BandwidthRow{}
	for _, r := range rows {
		byDay[r.Day] = r
	}
	out := make([]meta.BandwidthRow, 0, days)
	for i := 0; i < days; i++ {
		d := start.AddDate(0, 0, i)
		k := meta.BandwidthDay(d)
		r := meta.BandwidthRow{UserID: uid, Day: k}
		if v, ok := byDay[k]; ok {
			r.Up, r.Down = v.Up, v.Down
		}
		out = append(out, r)
	}
	// merge today's in-memory counters
	b.mu.Lock()
	if c := b.usage[uid]; c != nil && c.dayKey == meta.BandwidthDay(now) {
		out[len(out)-1].Up, out[len(out)-1].Down = c.up, c.down
	}
	b.mu.Unlock()
	return out, nil
}

// bwCtx carries the per-request counting state the wrappers use.
type bwCtx struct {
	m     *bwManager
	state atomic.Pointer[bwState]
}

type bwState struct {
	uid   string
	up    *bwlimit.Bucket
	down  *bwlimit.Bucket
	gUp   *bwlimit.Bucket
	gDown *bwlimit.Bucket
	pol   policy
}

type bwKeyT struct{}

var bwKey bwKeyT

// bandwidthMW installs a lazy counting context on /v1 requests. It is
// a no-op when the manager is nil or the route is /v1/events.
func (s *Server) bandwidthMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.bw == nil || !s.Cfg.Bandwidth.Enabled || r.URL.Path == "/v1/events" {
			next.ServeHTTP(w, r)
			return
		}
		c := &bwCtx{m: s.bw}
		r.Body = &bwBody{rc: r.Body, c: c, r: r}
		r2 := r.WithContext(context.WithValue(r.Context(), bwKey, c))
		next.ServeHTTP(&bwResponse{ResponseWriter: w, c: c}, r2)
	})
}

// bwAttach resolves the principal's tier buckets after authn. It is
// called from Server.authn with the request carrying a bwCtx when the
// bandwidth middleware wrapped the route.
func (s *Server) bwAttach(r *http.Request, p auth.Principal, w http.ResponseWriter) bool {
	if s.bw == nil || !s.Cfg.Bandwidth.Enabled {
		return true
	}
	c, _ := r.Context().Value(bwKey).(*bwCtx)
	if c == nil {
		return true
	}
	u := p.User
	e, err := s.Svc.Quota.For(u, "", p.Anonymous)
	var pol policy
	if err == nil {
		bp := e.Bandwidth
		pol = policy{upBps: bp.UpBps.Int64(), downBps: bp.DownBps.Int64(),
			daily: bp.Daily.Int64(), monthly: bp.Monthly.Int64()}
	}
	var upSize int64
	if r.Method != "GET" && r.Method != "HEAD" && r.ContentLength > 0 {
		upSize = r.ContentLength
	}
	capKind, hit := s.bw.check(r.Context(), u.ID, pol, upSize)
	if hit {
		c.state.Store(&bwState{uid: u.ID})
		s.bwReject(w, r, capKind)
		return false
	}
	c.state.Store(&bwState{
		uid: u.ID, pol: pol,
		up:   s.bw.up(u.ID, pol.upBps),
		down: s.bw.down(u.ID, pol.downBps),
		gUp:  s.bw.gUp, gDown: s.bw.gDown,
	})
	return true
}

// bwReject writes the 429 problem with Retry-After to the next UTC
// midnight or month start, whichever cap tripped.
func (s *Server) bwReject(w http.ResponseWriter, r *http.Request, capKind capResult) {
	now := s.bw.now().UTC()
	var reset time.Time
	if capKind == capMonthly {
		reset = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	} else {
		reset = time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	}
	after := int64(reset.Sub(now).Seconds()) + 1
	if after < 1 {
		after = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", after))
	if s.bw.met != nil {
		s.bw.met.BandwidthReject()
	}
	s.writeProblem(w, r, &api.Problem{
		Code: api.CodeBandwidthExceeded, Title: "bandwidth limit exceeded", Status: 429,
	})
}

// bwCount records n bytes for the request's user in the given
// direction and waits on the user and global buckets.
func (c *bwCtx) count(ctx context.Context, direction string, n int64) error {
	st := c.state.Load()
	if st == nil || n <= 0 {
		return nil
	}
	if direction == "up" {
		if err := st.up.Wait(ctx, int(n)); err != nil {
			return err
		}
		if err := st.gUp.Wait(ctx, int(n)); err != nil {
			return err
		}
		c.m.add(st.uid, n, 0)
		if c.m.met != nil {
			c.m.met.BandwidthBytes("up", n)
		}
	} else {
		if err := st.down.Wait(ctx, int(n)); err != nil {
			return err
		}
		if err := st.gDown.Wait(ctx, int(n)); err != nil {
			return err
		}
		c.m.add(st.uid, 0, n)
		if c.m.met != nil {
			c.m.met.BandwidthBytes("down", n)
		}
	}
	return nil
}

// bwBody wraps the request body, counting and throttling reads.
type bwBody struct {
	rc io.ReadCloser
	c  *bwCtx
	r  *http.Request
}

func (b *bwBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		_ = b.c.count(b.r.Context(), "up", int64(n))
	}
	return n, err
}
func (b *bwBody) Close() error { return b.rc.Close() }

// bwResponse counts and throttles writes while preserving Flush,
// Unwrap and ReadFrom.
type bwResponse struct {
	http.ResponseWriter
	c *bwCtx
}

func (w *bwResponse) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		// throttling errors are reported by the write itself next time
		_ = w.c.count(context.Background(), "down", int64(n))
	}
	return n, err
}
func (w *bwResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *bwResponse) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom disables sendfile so writes are counted and throttled.
func (w *bwResponse) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(w, r)
}
