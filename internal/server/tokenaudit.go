package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
)

// TokenAudit aggregates per-token usage and writes audit events off the
// request path.
type TokenAudit struct {
	meta     meta.Store
	trusted  []netip.Prefix
	realIP   string
	interval time.Duration
	clock    func() time.Time
	stop     chan struct{}
	done     chan struct{}
	evDone   chan struct{}
	log      *slog.Logger

	mu     sync.Mutex
	m      map[usageKey]*meta.UsageRow
	flush  chan struct{}
	closed bool
	drops  int64
	ewarn  time.Time
	ev     chan meta.TokenEvent
}

type usageKey struct {
	tok, ip string
	b       time.Time
}

// NewTokenAudit starts the usage aggregator and event writer.
func NewTokenAudit(m meta.Store, l *slog.Logger, trusted []netip.Prefix, realIP string, clock func() time.Time) *TokenAudit {
	a := &TokenAudit{meta: m, log: l, clock: clock, trusted: trusted, realIP: realIP, interval: 30 * time.Second,
		stop: make(chan struct{}), done: make(chan struct{}), evDone: make(chan struct{}), m: map[usageKey]*meta.UsageRow{},
		ev: make(chan meta.TokenEvent, 256), flush: make(chan struct{}, 1)}
	go a.loop()
	go a.evLoop()
	return a
}

// Add records one authenticated request. O(1), never touches the store.
func (a *TokenAudit) Add(tokenID string, r *http.Request, at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip := a.ip(r)
	ua := cleanUA(r.UserAgent())
	k := usageKey{tok: tokenID, ip: ip, b: at.UTC().Truncate(time.Hour)}
	row, ok := a.m[k]
	if !ok {
		if len(a.m) >= 10000 {
			a.drops++
			select {
			case a.flush <- struct{}{}:
			default:
				if a.now().Sub(a.ewarn) > time.Minute {
					a.ewarn = a.now()
					if a.log != nil {
						a.log.Warn("token audit buffer full", "drops", a.drops)
					}
				}
			}
			return
		}
		row = &meta.UsageRow{TokenID: tokenID, IP: ip, UserAgent: ua, Bucket: k.b}
		a.m[k] = row
	}
	row.Requests++
	row.LastSeen = at
	row.UserAgent = ua
}

func (a *TokenAudit) now() time.Time {
	if a.clock != nil {
		return a.clock()
	}
	return time.Now()
}

func (a *TokenAudit) curInterval() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.interval
}

func (a *TokenAudit) loop() {
	defer close(a.done)
	t := time.NewTicker(a.curInterval())
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.flushNow()
		case <-a.flush:
			a.flushNow()
		case <-a.stop:
			a.flushNow()
			return
		}
	}
}

func (a *TokenAudit) evLoop() {
	defer close(a.evDone)
	for e := range a.ev {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = a.meta.InsertTokenEvent(ctx, e)
		cancel()
	}
}

// Record queues one audit event, dropping when the channel is full.
func (a *TokenAudit) Record(e meta.TokenEvent) {
	defer func() { _ = recover() }()
	select {
	case a.ev <- e:
	default:
		a.mu.Lock()
		a.drops++
		a.mu.Unlock()
	}
}

func (a *TokenAudit) flushNow() {
	a.mu.Lock()
	batch := a.m
	a.m = map[usageKey]*meta.UsageRow{}
	a.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	rows := make([]meta.UsageRow, 0, len(batch))
	for _, r := range batch {
		rows = append(rows, *r)
	}
	pairs, err := a.meta.UpsertTokenUsage(context.Background(), rows)
	if err != nil {
		if a.log != nil {
			a.log.Warn("token usage flush", "err", err)
		}
		return
	}
	for _, p := range pairs {
		kind := "new_ip"
		if p.First {
			kind = "first_use"
		}
		id, _ := meta.NewID(a.now())
		a.Record(meta.TokenEvent{ID: id, TokenID: p.TokenID, At: a.now(), Kind: kind, IP: p.IP, Detail: "usage"})
	}
}

// Close stops the goroutines and flushes the last batch.
func (a *TokenAudit) Close(ctx context.Context) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	a.mu.Unlock()
	close(a.stop)
	<-a.done
	close(a.ev)
	select {
	case <-a.evDone:
	case <-ctx.Done():
	}
}

// clientIPAddr uses the one shared rule the server and auth agree on.
func (a *TokenAudit) ip(r *http.Request) string {
	return netx.ClientIPReal(r, a.trusted, a.realIP).String()
}

// cleanUA mirrors auth.cleanUA for this package's usage rows.
func cleanUA(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 32 && c != 127 {
			b.WriteRune(c)
		}
	}
	out := b.String()
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}
