// SPDX-License-Identifier: 0BSD

// Package quota resolves the effective limits for a (user, app) pair
// from the reloadable config view: tier quotas, per-user overrides,
// and per-app policy.
package quota

import (
	"errors"
	"regexp"
	"sync/atomic"

	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Resolver maps users and apps to effective limits.
type Resolver struct {
	cfg atomic.Pointer[config.Config]
}

// New returns a resolver bound to cfg; call Reload on config reload.
func New(cfg *config.Config) *Resolver {
	r := &Resolver{}
	r.cfg.Store(cfg)
	return r
}

// Reload swaps the config view atomically.
func (r *Resolver) Reload(cfg *config.Config) { r.cfg.Store(cfg) }

// Effective is the resolved limit set for one request.
type Effective struct {
	RequireEncryption    bool
	QuotaBytes           int64
	MaxSlots             int
	MaxPendingSnapshots  int
	KeepLast             int
	MaxAge               int64 // nanoseconds
	RequestsPerSec       float64
	Burst                int
	MaxConcurrentUploads int
	AllowForce           bool
	APILimits            api.Limits
}

var ErrUnknownApp = errors.New("quota: unknown app")

// For returns the effective limits. anonymous selects anonymous_tier.
// appID must already pass api.ValidateAppID.
func (r *Resolver) For(u meta.User, appID string, anonymous bool) (Effective, error) {
	c := r.cfg.Load()
	q := &c.Quota
	tierName := q.DefaultTier
	if anonymous {
		tierName = q.AnonymousTier
	} else if u.Tier != "" {
		tierName = u.Tier
	}
	t, ok := q.Tiers[tierName]
	if !ok {
		t = q.Tiers[q.DefaultTier]
	}
	e := Effective{
		RequireEncryption:    c.Limits.RequireEncryption,
		QuotaBytes:           t.QuotaBytes.Int64(),
		MaxSlots:             t.MaxSlots,
		MaxPendingSnapshots:  t.MaxPendingSnapshots,
		KeepLast:             t.Retention.KeepLast,
		MaxAge:               int64(t.Retention.MaxAge),
		RequestsPerSec:       t.Rate.RequestsPerSec,
		Burst:                t.Rate.Burst,
		MaxConcurrentUploads: t.MaxConcurrentUploads,
		APILimits:            c.Limits.APILimits(),
	}
	// Tier override for encryption requirement.
	if t.RequireEncryption != nil {
		e.RequireEncryption = *t.RequireEncryption
	}
	// Tier limits narrow the global api limits; zero means inherit.
	if t.MaxFiles > 0 && (e.APILimits.MaxFiles == 0 || t.MaxFiles < e.APILimits.MaxFiles) {
		e.APILimits.MaxFiles = t.MaxFiles
	}
	if t.MaxFileBytes > 0 && (e.APILimits.MaxFileBytes == 0 || t.MaxFileBytes.Int64() < e.APILimits.MaxFileBytes) {
		e.APILimits.MaxFileBytes = t.MaxFileBytes.Int64()
	}
	if t.MaxSnapshotBytes > 0 && (e.APILimits.MaxSnapshotBytes == 0 || t.MaxSnapshotBytes.Int64() < e.APILimits.MaxSnapshotBytes) {
		e.APILimits.MaxSnapshotBytes = t.MaxSnapshotBytes.Int64()
	}
	if t.MaxSnapshotsPerSlot > 0 && (e.KeepLast == 0 || t.MaxSnapshotsPerSlot < e.KeepLast) {
		e.KeepLast = t.MaxSnapshotsPerSlot
	}
	if u.QuotaBytes != nil {
		e.QuotaBytes = *u.QuotaBytes
	}
	// App policy.
	if pol, ok := q.Apps[appID]; ok {
		e.AllowForce = pol.AllowForce
		if pol.Retention != nil {
			e.KeepLast = pol.Retention.KeepLast
			e.MaxAge = int64(pol.Retention.MaxAge)
		}
		if pol.MaxFileBytes > 0 {
			e.APILimits.MaxFileBytes = pol.MaxFileBytes.Int64()
		}
		if pol.MaxSnapshotBytes > 0 {
			e.APILimits.MaxSnapshotBytes = pol.MaxSnapshotBytes.Int64()
		}
	} else {
		if q.AllowUnknownApps == "" {
			return e, ErrUnknownApp
		}
		re, err := regexp.Compile(q.AllowUnknownApps)
		if err != nil || !re.MatchString(appID) {
			return e, ErrUnknownApp
		}
	}
	return e, nil
}

// MetaLimits projects Effective into meta.BeginLimits.
func (e Effective) MetaLimits(expiresAt int64) meta.BeginLimits {
	return meta.BeginLimits{
		QuotaBytes:          e.QuotaBytes,
		MaxSlots:            e.MaxSlots,
		MaxPendingSnapshots: e.MaxPendingSnapshots,
	}
}
