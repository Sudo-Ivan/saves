// SPDX-License-Identifier: 0BSD

package tray

import (
	"testing"

	"github.com/Sudo-Ivan/saves/internal/notify"
)

type fakeN struct{ calls []string }

func (f *fakeN) Notify(t, b string, u notify.Urgency) error {
	f.calls = append(f.calls, t+":"+b)
	return nil
}

func TestLogTailer(t *testing.T) {
	f := &fakeN{}
	lt := &LogTailer{N: f, Enabled: true}
	lt.Feed("conflict", "g/s", "conflict")
	if len(f.calls) != 1 {
		t.Fatal("conflict not notified")
	}
	lt.Feed("conflict", "g/s", "conflict") // dedup
	if len(f.calls) != 1 {
		t.Fatal("dedup failed")
	}
	for i := 0; i < 5; i++ {
		lt.Feed("error", "g/s", "e")
	}
	if len(f.calls) < 2 {
		t.Fatal("streak not notified")
	}
}
