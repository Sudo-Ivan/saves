// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

// Audit action names.
const (
	actLoginOK     = "login_ok"
	actLoginFail   = "login_fail"
	actLockout     = "lockout"
	actLogout      = "logout"
	actPwChange    = "password_change"
	act2FAOn       = "2fa_enable"
	act2FAOff      = "2fa_disable"
	actRecovery    = "recovery_use"
	actSessRevoke  = "session_revoke"
	actBan         = "ban"
	actUnban       = "unban"
	actApprove     = "approve"
	actReject      = "reject"
	actIPBlock     = "ip_blocked"
	actSetPassword = "admin_set_password"
	actSettings    = "settings.change"
)

// Auditor batches audit events to the store. Nil receivers are safe.
type Auditor struct {
	store meta.Store
	clock func() time.Time
	ch    chan meta.AuditEvent
	done  chan struct{}
	wg    sync.WaitGroup
	drops uint64
}

// NewAuditor returns an Auditor; store and clock may be nil.
func NewAuditor(store meta.Store, clock func() time.Time) *Auditor {
	if clock == nil {
		clock = time.Now
	}
	return &Auditor{store: store, clock: clock, ch: make(chan meta.AuditEvent, 512), done: make(chan struct{})}
}

// Record writes one event synchronously (admin actions).
func (a *Auditor) Record(ctx context.Context, e meta.AuditEvent) {
	if a == nil || a.store == nil {
		return
	}
	if e.ID == "" {
		e.ID, _ = meta.NewID(e.At)
	}
	if e.At.IsZero() {
		e.At = a.clock()
	}
	_ = a.store.InsertAudit(ctx, []meta.AuditEvent{e})
}

// Add queues one event asynchronously, dropping when full.
func (a *Auditor) Add(e meta.AuditEvent) {
	if a == nil {
		return
	}
	select {
	case a.ch <- e:
	default:
		a.drops++
	}
}

// Start runs the flush loop.
func (a *Auditor) Start() {
	a.wg.Add(1)
	go a.loop()
}

func (a *Auditor) loop() {
	defer a.wg.Done()
	var buf []meta.AuditEvent
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	flush := func() {
		if len(buf) == 0 {
			return
		}
		for _, e := range buf {
			if e.ID == "" {
				e.ID, _ = meta.NewID(e.At)
			}
		}
		_ = a.store.InsertAudit(context.Background(), buf)
		buf = nil
	}
	for {
		select {
		case e := <-a.ch:
			buf = append(buf, e)
			if len(buf) >= 64 {
				flush()
			}
		case <-t.C:
			flush()
		case <-a.done:
			flush()
			return
		}
	}
}

// Close flushes and stops.
func (a *Auditor) Close(ctx context.Context) {
	if a == nil {
		return
	}
	close(a.done)
	a.wg.Wait()
}
