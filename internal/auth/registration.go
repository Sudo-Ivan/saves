// SPDX-License-Identifier: 0BSD

package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

// Registration handles self service signup.
type Registration struct {
	Mode        RegistrationMode
	Meta        meta.Store
	Invites     map[string]*Invite
	DefaultTier string
	Limiter     *ratelimit.Limiter // per-IP
	Clock       func() time.Time

	mu sync.Mutex
}

// Result is returned once per registration.
type Result struct {
	User      meta.User
	TokenID   string
	Token     string
	CreatedAt time.Time
}

// Register validates the invite (when in invite mode), creates the
// user, and mints the first token, returning the secret once.
func (rg *Registration) Register(ctx context.Context, ip, inviteCode string) (*Result, error) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	if rg.Mode == RegClosed {
		return nil, ErrRegistrationClosed
	}
	if rg.Limiter != nil {
		if ok, _ := rg.Limiter.Allow(ip, 1); !ok {
			return nil, ErrRateLimited
		}
	}
	var inv *Invite
	switch rg.Mode {
	case RegInvite:
		inv = rg.Invites[inviteCode]
		if inv == nil || (inv.MaxUses > 0 && inv.Uses >= inv.MaxUses) {
			return nil, ErrBadInvite
		}
	case RegOpen:
		// no check
	}
	subject, err := randomSubject()
	if err != nil {
		return nil, err
	}
	u, _, err := rg.Meta.UpsertUser(ctx, subject, rg.DefaultTier)
	if err != nil {
		return nil, err
	}
	id, _, full, hash, err := GenerateToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if rg.Clock != nil {
		now = rg.Clock()
	}
	if err := rg.Meta.CreateToken(ctx, meta.Token{
		ID: id, UserID: u.ID, SecretHash: hash, Name: "initial",
		Scopes: []string{"read", "write"}, CreatedAt: now,
	}); err != nil {
		return nil, err
	}
	if inv != nil {
		inv.Uses++
	}
	return &Result{User: u, TokenID: id, Token: full, CreatedAt: now}, nil
}

func randomSubject() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "user:" + hex.EncodeToString(b[:]), nil
}
