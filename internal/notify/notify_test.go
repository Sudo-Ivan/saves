// SPDX-License-Identifier: 0BSD

package notify

import (
	"testing"
	"time"
)

type fake struct{ calls int }

func (f *fake) Notify(t, b string, u Urgency) error { f.calls++; return nil }

func TestDedup(t *testing.T) {
	f := &fake{}
	now := time.Now()
	d := &Dedup{Inner: f, Window: time.Minute, Now: func() time.Time { return now },
		last: map[string]time.Time{}}
	d.Notify("t", "b", Normal)
	d.Notify("t", "b", Normal)
	if f.calls != 1 {
		t.Fatalf("dedup %d calls", f.calls)
	}
	now = now.Add(2 * time.Minute)
	d.Notify("t", "b", Normal)
	if f.calls != 2 {
		t.Fatal("resend after window")
	}
	d.Notify("t", "b2", Normal)
	if f.calls != 3 {
		t.Fatal("different body suppressed")
	}
}
