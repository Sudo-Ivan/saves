// SPDX-License-Identifier: 0BSD

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/ratelimit"
)

// RegistrationMode controls signup.
type RegistrationMode int

const (
	RegClosed RegistrationMode = iota
	RegInvite
	RegOpen
)

var ErrRegistrationClosed = errors.New("auth: registration closed")
var ErrBadInvite = errors.New("auth: invalid invite")

// Invite tracks a multi-use invite code.
type Invite struct {
	Code    string
	MaxUses int
	Uses    int
}

// ErrPendingApproval marks a registration that created a pending user.
var ErrPendingApproval = errors.New("auth: pending approval")

// Registration handles self service signup.
type Registration struct {
	Mode        RegistrationMode
	Meta        meta.Store
	Invites     map[string]*Invite
	DefaultTier string
	Limiter     *ratelimit.Limiter // per-IP
	Clock       func() time.Time
	// Effective returns live settings values; nil falls back to Mode.
	Effective func() RegistrationSettings
	// Audit records one audit event; nil is fine.
	Audit func(ctx context.Context, e meta.AuditEvent)
	// Signup counts a registration; nil is fine.
	Signup func()

	mu     sync.Mutex
	perSec float64
}

// RegistrationSettings is the live registration policy.
type RegistrationSettings struct {
	Mode            RegistrationMode
	PerSec          float64
	RequireApproval bool
	MaxPerIPDay     int
}

func (rg *Registration) effective() RegistrationSettings {
	if rg.Effective != nil {
		return rg.Effective()
	}
	return RegistrationSettings{Mode: rg.Mode}
}

func (rg *Registration) limiterFor(ps float64) *ratelimit.Limiter {
	if ps != rg.perSec {
		rg.perSec = ps
		if ps <= 0 {
			rg.Limiter = nil
		} else {
			rg.Limiter = ratelimit.New(ps, 1, 1<<16, rg.Clock)
		}
	}
	return rg.Limiter
}

// Result is returned once per registration.
type Result struct {
	User      meta.User
	TokenID   string
	Token     string
	CreatedAt time.Time
}

// check enforces mode, rate limit, and invite validity, returning the
// invite to mark used on success.
// check enforces mode, the per-IP rate limit and the daily cap. The
// invite itself is consumed later once the user exists.
func (rg *Registration) check(ctx context.Context, ip string) (RegistrationSettings, error) {
	eff := rg.effective()
	if eff.Mode == RegClosed {
		return eff, ErrRegistrationClosed
	}
	if l := rg.limiterFor(eff.PerSec); l != nil {
		if ok, _ := l.Allow(ip, 1); !ok {
			return eff, ErrRateLimited
		}
	}
	if eff.MaxPerIPDay > 0 {
		evs, _, err := rg.Meta.ListAudit(ctx, meta.AuditFilter{Action: "register",
			From: rg.now().Add(-24 * time.Hour)}, "", 200)
		if err == nil {
			n := 0
			for _, e := range evs {
				if e.IP == ip {
					n++
				}
			}
			if n >= eff.MaxPerIPDay {
				return eff, ErrRateLimited
			}
		}
	}
	return eff, nil
}

func (rg *Registration) now() time.Time {
	if rg.Clock != nil {
		return rg.Clock()
	}
	return time.Now()
}

// consumeInvite atomically uses the code; any failure is the same
// generic ErrBadInvite.
func (rg *Registration) consumeInvite(ctx context.Context, code, userID, ip string) error {
	h := sha256.Sum256([]byte(strings.TrimSpace(code)))
	if err := rg.Meta.ConsumeInvite(ctx, h, userID, ip); err != nil {
		return ErrBadInvite
	}
	return nil
}

// afterUser writes the register audit event and the pending status.
func (rg *Registration) afterUser(ctx context.Context, eff RegistrationSettings, u meta.User, ip string) error {
	if rg.Signup != nil {
		rg.Signup()
	}
	if rg.Audit != nil {
		id, _ := meta.NewID(rg.now())
		rg.Audit(ctx, meta.AuditEvent{ID: id, At: rg.now(), Action: "register",
			TargetType: "user", TargetID: u.ID, IP: ip})
	}
	if eff.RequireApproval {
		return rg.Meta.SetUserStatus(ctx, meta.UserStatus{
			UserID: u.ID, State: "pending", At: rg.now()})
	}
	return nil
}

// Register validates the invite (when in invite mode), creates the
// user, and mints the first token, returning the secret once.
func (rg *Registration) Register(ctx context.Context, ip, inviteCode string) (*Result, error) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	eff, err := rg.check(ctx, ip)
	if err != nil {
		return nil, err
	}
	subject, err := randomSubject()
	if err != nil {
		return nil, err
	}
	u, _, err := rg.Meta.UpsertUser(ctx, subject, rg.DefaultTier)
	if err != nil {
		return nil, err
	}
	if eff.Mode == RegInvite {
		if err := rg.consumeInvite(ctx, inviteCode, u.ID, ip); err != nil {
			return nil, err
		}
	}
	if err := rg.afterUser(ctx, eff, u, ip); err != nil {
		return nil, err
	}
	now := rg.now()
	if eff.RequireApproval {
		return &Result{User: u, CreatedAt: now}, ErrPendingApproval
	}
	id, _, full, hash, err := GenerateToken()
	if err != nil {
		return nil, err
	}
	if err := rg.Meta.CreateToken(ctx, meta.Token{
		ID: id, UserID: u.ID, SecretHash: hash, Name: "initial",
		Scopes: []string{"read", "write"}, CreatedAt: now,
	}); err != nil {
		return nil, err
	}
	return &Result{User: u, TokenID: id, Token: full, CreatedAt: now}, nil
}

// RegisterNoToken validates like Register but creates only the user,
// without an initial API token. Web signup uses this.
func (rg *Registration) RegisterNoToken(ctx context.Context, ip, inviteCode string) (meta.User, error) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	eff, err := rg.check(ctx, ip)
	if err != nil {
		return meta.User{}, err
	}
	subject, err := randomSubject()
	if err != nil {
		return meta.User{}, err
	}
	u, _, err := rg.Meta.UpsertUser(ctx, subject, rg.DefaultTier)
	if err != nil {
		return meta.User{}, err
	}
	if eff.Mode == RegInvite {
		if err := rg.consumeInvite(ctx, inviteCode, u.ID, ip); err != nil {
			return meta.User{}, err
		}
	}
	if err := rg.afterUser(ctx, eff, u, ip); err != nil {
		return meta.User{}, err
	}
	return u, nil
}

func randomSubject() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "user:" + hex.EncodeToString(b[:]), nil
}
