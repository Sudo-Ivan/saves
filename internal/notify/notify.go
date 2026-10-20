// SPDX-License-Identifier: 0BSD

// Package notify delivers desktop notifications with de-duplication.
package notify

import (
	"os/exec"
	"sync"
	"time"
)

// Urgency is the freedesktop urgency level.
type Urgency int

const (
	Low Urgency = iota
	Normal
	Critical
)

// Notifier sends a desktop notification.
type Notifier interface {
	Notify(title, body string, urgency Urgency) error
}

// NopNotifier drops notifications silently.
type NopNotifier struct{}

func (NopNotifier) Notify(title, body string, u Urgency) error { return nil }

// Dedup wraps a Notifier suppressing repeats within window.
type Dedup struct {
	Inner  Notifier
	Window time.Duration
	Now    func() time.Time
	mu     sync.Mutex
	last   map[string]time.Time
}

// NewDedup wraps n with a 60 s window.
func NewDedup(n Notifier) *Dedup {
	return &Dedup{Inner: n, Window: 60 * time.Second,
		Now: time.Now, last: map[string]time.Time{}}
}

func (d *Dedup) Notify(title, body string, u Urgency) error {
	d.mu.Lock()
	if d.last == nil {
		d.last = map[string]time.Time{}
	}
	key := title + "\x00" + body
	now := d.Now()
	if last, ok := d.last[key]; ok && now.Sub(last) < d.Window {
		d.mu.Unlock()
		return nil
	}
	d.last[key] = now
	d.mu.Unlock()
	return d.Inner.Notify(title, body, u)
}

// DbusNotifier sends via org.freedesktop.Notifications.
type DbusNotifier struct {
	// Send performs the actual Notify call; injectable.
	Send func(title, body string, urg Urgency) error
}

func (d DbusNotifier) Notify(title, body string, u Urgency) error {
	if d.Send != nil {
		return d.Send(title, body, u)
	}
	return nil
}

// ExecNotifier falls back to notify-send.
type ExecNotifier struct {
	Run func(name string, args ...string) error
}

func (e ExecNotifier) Notify(title, body string, u Urgency) error {
	run := e.Run
	if run == nil {
		run = func(n string, a ...string) error { return exec.Command(n, a...).Run() } // #nosec G204 -- argv slice built by this program, no shell
	}
	u2 := "normal"
	if u == Low {
		u2 = "low"
	} else if u == Critical {
		u2 = "critical"
	}
	return run("notify-send", "-u", u2, "--", title, body)
}
