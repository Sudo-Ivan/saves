// SPDX-License-Identifier: 0BSD

package tray

import (
	"time"

	"github.com/Sudo-Ivan/saves/internal/notify"
)

// LogTailer reports new daemon log events as notifications.
type LogTailer struct {
	N         notify.Notifier
	Enabled   bool
	errStreak int
	seen      map[string]time.Time
}

// Feed processes a new daemon log entry and notifies when warranted.
func (t *LogTailer) Feed(level, game, msg string) {
	if !t.Enabled || t.N == nil {
		return
	}
	if t.seen == nil {
		t.seen = map[string]time.Time{}
	}
	if level == "error" {
		t.errStreak++
		if t.errStreak >= 3 {
			_ = t.N.Notify("saves", "repeated sync errors on "+game, notify.Normal)
			t.errStreak = 0
		}
		return
	}
	if msg == "sync ok" {
		t.errStreak = 0
	}
	key := level + "|" + msg
	if ts, ok := t.seen[key]; ok && time.Since(ts) < 60*time.Second {
		return
	}
	t.seen[key] = time.Now()
	if level == "conflict" {
		_ = t.N.Notify("saves", "conflict in "+game+" needs a choice", notify.Critical)
		t.errStreak = 0
	}
}
