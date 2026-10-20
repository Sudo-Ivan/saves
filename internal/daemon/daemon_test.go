// SPDX-License-Identifier: 0BSD

package daemon

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeSync struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeSync) Sync(ctx context.Context, game, policy string) (SyncResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, game)
	f.mu.Unlock()
	return SyncResult{}, nil
}

func (f *fakeSync) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestDaemonSM(t *testing.T) {
	f := &fakeSync{}
	d := New(Config{QuietPeriod: 0}, f)
	d.Register("g1", "slot")
	d.Note("g1")
	paused, games := d.Status()
	if games["g1"].State != "quiet" || paused {
		t.Fatalf("state %+v", games)
	}
	d.SyncNow("g1")
	if f.n() != 1 {
		t.Fatalf("calls %v", f.calls)
	}
	if d.Status(); true {
	}
	d.Pause("")
	paused, _ = d.Status()
	if !paused {
		t.Fatal("not paused")
	}
	d.Resume("")
	d.Stop()
}

func TestScheduler(t *testing.T) {
	f := &fakeSync{}
	d := New(Config{QuietPeriod: 5 * time.Millisecond, MaxParallel: 2}, f)
	d.Register("g1", "s")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	d.NoteLocal("g1")
	time.Sleep(1300 * time.Millisecond)
	if f.n() == 0 {
		t.Fatal("no sync after quiet")
	}
	d.Stop()
	<-done
	// Resolve path
	d.mu.Lock()
	d.games["g1"].Conflict = true
	d.mu.Unlock()
	if got := d.Conflicts(); len(got) != 1 {
		t.Fatal("conflict not listed")
	}
	if err := d.Resolve("g1", "keep-newest"); err != nil {
		t.Fatal(err)
	}
	if len(d.Conflicts()) != 0 {
		t.Fatal("conflict not cleared")
	}
}

// TestRaceStress hammers the daemon concurrently.
func TestRaceStress(t *testing.T) {
	d := New(Config{QuietPeriod: time.Millisecond}, &fakeSync{})
	d.Register("g", "s")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				d.Pause("")
				d.Resume("")
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				d.NoteLocal("g")
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				d.Remote("g")
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				d.Status()
				d.Logs(5)
			}
		}()
	}
	wg.Wait()
}
