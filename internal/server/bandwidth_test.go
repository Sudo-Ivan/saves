package server

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
)

func bwStore(t *testing.T) meta.Store {
	st, err := sqlite.Open(t.TempDir()+"/bw.db", meta.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestBWFlushAndCaps(t *testing.T) {
	st := bwStore(t)
	c := testclock.New(time.Date(2027, 5, 1, 10, 0, 0, 0, time.UTC))
	b := newBwManager(st, c.NowFunc())
	b.met = nil
	// accumulate and flush once
	b.add("u1", 100, 50)
	b.add("u1", 20, 0)
	b.flush()
	rows, _ := st.BandwidthUsage(context.Background(), "u1",
		meta.BandwidthDay(c.Now()), meta.BandwidthDay(c.Now()))
	if len(rows) != 1 || rows[0].Up != 120 || rows[0].Down != 50 {
		t.Fatalf("rows=%v", rows)
	}
	// second flush adds nothing
	b.flush()
	rows, _ = st.BandwidthUsage(context.Background(), "u1",
		meta.BandwidthDay(c.Now()), meta.BandwidthDay(c.Now()))
	if rows[0].Up != 120 {
		t.Fatalf("double count: %v", rows)
	}
	// cap decision at exactly the cap
	pol := policy{daily: 170}
	if _, hit := b.check(context.Background(), "u1", pol, 0); !hit {
		t.Fatal("should trip daily at 170")
	}
	if _, hit := b.check(context.Background(), "u1", policy{daily: 200}, 0); hit {
		t.Fatal("200 cap should pass at 170")
	}
	// declared upload size counts
	if _, hit := b.check(context.Background(), "u1", policy{daily: 200}, 40); !hit {
		t.Fatal("content-length should trip")
	}
	// monthly cap
	if _, hit := b.check(context.Background(), "u1", policy{monthly: 170}, 0); !hit {
		t.Fatal("monthly cap")
	}
	// rollover at UTC midnight: counters reset
	c.Add(20 * time.Hour)
	b.add("u1", 5, 0)
	cnt := b.counter(context.Background(), "u1")
	if cnt.up != 5 {
		t.Fatalf("rollover: %d", cnt.up)
	}
	// month rollover
	b.flush()
	c.Add(40 * 24 * time.Hour)
	b.add("u1", 7, 0)
	cnt2 := b.counter(context.Background(), "u1")
	if cnt2.mUp != 7 {
		t.Fatalf("month rollover: %d", cnt2.mUp)
	}
}

func TestBWLazyLoadAndClose(t *testing.T) {
	st := bwStore(t)
	d := meta.BandwidthDay(time.Now())
	_ = st.AddBandwidth(context.Background(), []meta.BandwidthRow{
		{UserID: "u2", Day: d, Up: 999, Down: 1}})
	b := newBwManager(st, time.Now)
	cnt := b.counter(context.Background(), "u2")
	if !cnt.loaded || cnt.up != 999 {
		t.Fatalf("lazy load: %+v", cnt)
	}
	b.add("u2", 10, 0)
	b.Close()
	rows, _ := st.BandwidthUsage(context.Background(), "u2", d, d)
	if rows[0].Up != 1009 {
		t.Fatalf("close flush: %v", rows)
	}
}

func TestBWMe(t *testing.T) {
	f := setup(t)
	f.s2.bw = newBwManager(f.m, time.Now)
	tok := f.tokenFor(t, "u", []string{"read"}, nil)
	r := f.do(t, "GET", "/v1/me", nil, map[string]string{"Authorization": "Bearer " + tok})
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	sb := string(b)
	if !strings.Contains(sb, `"enabled":true`) {
		t.Fatalf("me: %s", sb)
	}
}
