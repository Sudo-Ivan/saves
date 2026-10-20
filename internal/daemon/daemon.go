// SPDX-License-Identifier: 0BSD

// Package daemon runs the background sync loop. Watchers are injectable
// for tests; fsnotify is used on the real system, with a poll fallback.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// State is a per-game worker state.
type State int

const (
	Idle State = iota
	Watching
	Quiet
	Syncing
	Paused
	Locked
	Conflict
	Failed
)

// LogEntry is one ring buffer event.
type LogEntry struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Game  string    `json:"game"`
	Msg   string    `json:"message"`
}

// GameStatus is the exported status of one tracked game.
type GameStatus struct {
	ID        string    `json:"id"`
	Slot      string    `json:"slot"`
	State     string    `json:"state"`
	LastSync  time.Time `json:"last_sync,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Conflict  bool      `json:"pending_conflict"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
}

// SyncResult reports a finished sync.
type SyncResult struct {
	BytesUp   int64
	BytesDown int64
	Unchanged bool
	Duration  time.Duration
}

// Syncer does the real sync work (client Push/Pull).
type Syncer interface {
	Sync(ctx context.Context, game string, policy string) (SyncResult, error)
}

// Watcher reports local changes for a game root.
type Watcher interface {
	Watch(ctx context.Context, dir string) (<-chan string, error)
}

// Config holds daemon knobs (clicfg.Daemon).
type Config struct {
	QuietPeriod  time.Duration
	PollInterval time.Duration
	MaxParallel  int
	HardCap      time.Duration
}

// Daemon coordinates workers.
type Daemon struct {
	cfg     Config
	sync    Syncer
	clock   func() time.Time
	mu      sync.Mutex
	games   map[string]*GameStatus
	logs    []LogEntry
	paused  bool
	reach   atomic.Bool
	stopC   chan struct{}
	changes map[string]time.Time
	chg     map[string]chan string
	events  map[string]func() // cancel
}

// New makes a daemon.
func New(c Config, s Syncer) *Daemon {
	return &Daemon{cfg: c, sync: s, games: map[string]*GameStatus{},
		changes: map[string]time.Time{}, stopC: make(chan struct{}),
		events: map[string]func(){}}
}

var ErrPaused = errors.New("daemon: paused")

// Note marks a game dir as locally changed (starts quiet countdown).
func (d *Daemon) Note(game string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.changes[game] = d.now()
	if g := d.games[game]; g != nil {
		g.State = "quiet"
	}
}

// Remote marks a game dirty-remote; the loop runs a serialized sync.
func (d *Daemon) Remote(game string) {
	select {
	case d.changeC(game) <- "@remote":
	default:
	}
}

func (d *Daemon) now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}

func (d *Daemon) log(level, game, msg string) {
	d.mu.Lock()
	d.logs = append(d.logs, LogEntry{Time: d.now(), Level: level, Game: game, Msg: msg})
	if len(d.logs) > 1000 {
		d.logs = d.logs[len(d.logs)-1000:]
	}
	d.mu.Unlock()
}

// Logs returns recent entries.
func (d *Daemon) Logs(n int) []LogEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n <= 0 || n > len(d.logs) {
		n = len(d.logs)
	}
	return append([]LogEntry(nil), d.logs[len(d.logs)-n:]...)
}

// Status returns per-game states.
// Reachable reports the server reachability flag.
func (d *Daemon) Reachable() bool { return d.reach.Load() }

// SetReachable flips the reachability flag.
func (d *Daemon) SetReachable(ok bool) { d.reach.Store(ok) }

// RemoteAll triggers a remote-dirty sync for every game.
func (d *Daemon) RemoteAll() {
	d.mu.Lock()
	ids := make([]string, 0, len(d.games))
	for k := range d.games {
		ids = append(ids, k)
	}
	d.mu.Unlock()
	for _, k := range ids {
		d.Remote(k)
	}
}

func (d *Daemon) Status() (paused bool, games map[string]GameStatus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	games = map[string]GameStatus{}
	for k, v := range d.games {
		games[k] = *v
	}
	return d.paused, games
}

// Register adds a game to watch.
func (d *Daemon) Register(id, slot string) {
	d.mu.Lock()
	if d.games[id] == nil {
		d.games[id] = &GameStatus{ID: id, Slot: slot, State: "idle"}
	}
	d.mu.Unlock()
}

// Pause pauses all or one game.
func (d *Daemon) Pause(game string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if game == "" {
		d.paused = true
		return
	}
	if g := d.games[game]; g != nil {
		g.State = "paused"
	}
}

// Resume unpauses and nudges the game so a change consumed while
// paused is resynced.
func (d *Daemon) Resume(game string) {
	d.mu.Lock()
	if game == "" {
		d.paused = false
		for k := range d.games {
			if d.games[k].State == "paused" {
				d.games[k].State = "idle"
			}
		}
	} else if g := d.games[game]; g != nil && g.State == "paused" {
		g.State = "idle"
	}
	d.mu.Unlock()
	if game != "" {
		d.NoteLocal(game)
		return
	}
	d.mu.Lock()
	var all []string
	for k := range d.games {
		all = append(all, k)
	}
	d.mu.Unlock()
	for _, k := range all {
		d.NoteLocal(k)
	}
}

// trySync runs the syncer for a game.
func (d *Daemon) trySync(game string) {
	d.mu.Lock()
	g := d.games[game]
	if g == nil || d.paused || g.State == "paused" {
		d.mu.Unlock()
		return
	}
	g.State = "syncing"
	d.mu.Unlock()
	d.log("info", game, "sync start")
	sr, err := d.sync.Sync(context.Background(), game, "")
	d.mu.Lock()
	g.LastSync = d.now()
	var msg string
	if err != nil {
		g.State = "error"
		g.LastError = err.Error()
		msg = "error: " + err.Error()
	} else {
		g.State = "idle"
		g.LastError = ""
		g.BytesUp += sr.BytesUp
		g.BytesDown += sr.BytesDown
		msg = fmt.Sprintf("sync ok up=%d down=%d in %s", sr.BytesUp, sr.BytesDown, sr.Duration)
	}
	d.mu.Unlock()
	d.log("info", game, msg)
}

// SyncNow syncs one or all games.
func (d *Daemon) SyncNow(game string) {
	if game != "" {
		d.trySync(game)
		return
	}
	d.mu.Lock()
	ids := make([]string, 0, len(d.games))
	for k := range d.games {
		ids = append(ids, k)
	}
	d.mu.Unlock()
	for _, k := range ids {
		d.trySync(k)
	}
}

// Stop cancels in-flight work.
func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.stopC:
	default:
		close(d.stopC)
	}
}

// Run starts one worker per registered game and blocks until ctx ends.
func (d *Daemon) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-d.stopC:
			cancel()
		case <-ctx.Done():
		}
	}()
	sem := make(chan struct{}, max(1, d.cfg.MaxParallel))
	seen := map[string]chan struct{}{}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		d.mu.Lock()
		var cur []string
		for k := range d.games {
			cur = append(cur, k)
		}
		d.mu.Unlock()
		curSet := map[string]bool{}
		for _, id := range cur {
			curSet[id] = true
			if seen[id] == nil {
				stop := make(chan struct{})
				seen[id] = stop
				wctx, wc := context.WithCancel(ctx)
				go func() {
					<-stop
					wc()
				}()
				go func(game string) {
					d.loop(wctx, game, sem)
				}(id)
			}
		}
		for id, stop := range seen {
			if !curSet[id] {
				close(stop)
				delete(seen, id)
			}
		}
		select {
		case <-ctx.Done():
			for id := range seen {
				close(seen[id])
				delete(seen, id)
			}
			return
		case <-tick.C:
		}
	}
}

// Unregister removes a game's worker.
func (d *Daemon) Unregister(id string) {
	d.mu.Lock()
	delete(d.games, id)
	d.mu.Unlock()
}

// loop is the per-game state machine: watch -> quiet -> sync -> backoff.
func (d *Daemon) loop(ctx context.Context, game string, sem chan struct{}) {
	d.mu.Lock()
	g := d.games[game]
	if g == nil {
		d.mu.Unlock()
		return
	}
	g.State = "watching"
	d.mu.Unlock()
	var quietAt time.Time
	dirtyRemote := false
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.changeC(game):
			d.mu.Lock()
			if ev == "@remote" {
				dirtyRemote = true
			} else {
				g.State = "quiet"
				quietAt = d.now()
			}
			d.mu.Unlock()
		case <-tick.C:
			d.mu.Lock()
			paused := d.paused || g.State == "paused"
			lockDue := g.State == "locked" && g.LastSync.Add(30*time.Second).Before(d.now())
			if lockDue {
				g.State = "quiet"
				quietAt = d.now()
			}
			quietDue := g.State == "quiet" && !quietAt.IsZero() &&
				d.now().Sub(quietAt) >= d.cfg.QuietPeriod
			remoteDue := dirtyRemote && g.State != "paused"
			d.mu.Unlock()
			if paused {
				continue
			}
			d.mu.Lock()
			if quietDue && g.LastSync.After(d.now().Add(-2*time.Second)) {
				quietDue = false
				quietAt = time.Time{}
				g.State = "idle"
			}
			d.mu.Unlock()
			if quietDue || remoteDue {
				dirtyRemote = false
				d.mu.Lock()
				g.State = "syncing"
				d.mu.Unlock()
				sem <- struct{}{}
				sr, err := d.sync.Sync(ctx, game, "")
				<-sem
				d.mu.Lock()
				g.LastSync = d.now()
				switch {
				case errors.Is(err, ErrLocked):
					g.State = "locked"
					g.LastError = "world locked"
				case errors.Is(err, ErrConflict):
					g.State = "conflict"
					g.Conflict = true
				case err != nil:
					g.State = "error"
					g.LastError = err.Error()
				default:
					g.State = "idle"
					g.LastError = ""
					g.BytesUp += sr.BytesUp
					g.BytesDown += sr.BytesDown
				}
				quietAt = time.Time{}
				d.mu.Unlock()
			}
		}
	}
}

// changeC returns the change channel for a game.
func (d *Daemon) changeC(game string) chan string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.chg == nil {
		d.chg = map[string]chan string{}
	}
	ch := d.chg[game]
	if ch == nil {
		ch = make(chan string, 16)
		d.chg[game] = ch
	}
	return ch
}

// NoteLocal feeds a watcher event into the state machine.
func (d *Daemon) NoteLocal(game string) {
	select {
	case d.changeC(game) <- "change":
	default:
	}
}

// Resolve records a conflict choice and resyncs with that policy.
func (d *Daemon) Resolve(game, choice string) error {
	d.mu.Lock()
	g := d.games[game]
	if g == nil {
		d.mu.Unlock()
		return ErrPaused
	}
	g.Conflict = false
	g.State = "idle"
	d.mu.Unlock()
	d.log("info", game, "resolved "+choice)
	go d.syncWith(game, choice)
	return nil
}

// syncWith runs a sync carrying an explicit policy choice.
func (d *Daemon) syncWith(game, choice string) {
	d.mu.Lock()
	g := d.games[game]
	if g == nil {
		d.mu.Unlock()
		return
	}
	g.State = "syncing"
	d.mu.Unlock()
	d.log("info", game, "sync start")
	sr, err := d.sync.Sync(context.Background(), game, choice)
	d.mu.Lock()
	g.LastSync = d.now()
	msg := "sync ok"
	if err != nil {
		g.State = "error"
		g.LastError = err.Error()
		msg = "error: " + err.Error()
	} else {
		g.State = "idle"
		g.BytesUp += sr.BytesUp
		g.BytesDown += sr.BytesDown
		msg = fmt.Sprintf("sync ok up=%d down=%d in %s", sr.BytesUp, sr.BytesDown, sr.Duration)
	}
	d.mu.Unlock()
	d.log("info", game, msg)
}

// Conflicts lists games waiting for a user choice.
func (d *Daemon) Conflicts() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for k, g := range d.games {
		if g.Conflict {
			out = append(out, k)
		}
	}
	return out
}

// Sentinels the scheduler treats specially.
var (
	// ErrLocked means the world is locked; the daemon retries later.
	ErrLocked = errors.New("daemon: world locked")
	// ErrConflict means the policy is ask and user input is needed.
	ErrConflict = errors.New("daemon: conflict needs resolve")
)
