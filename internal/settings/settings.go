// SPDX-License-Identifier: 0BSD

// Package settings provides runtime-tunable settings persisted as
// per-key overrides in the meta store.
package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
)

// Values is the live settings set. Every field maps to a stable key.
type Values struct {
	RegMode          string                 `json:"registration.mode"`               // closed, invite or open
	RegApproval      bool                   `json:"registration.require_approval"`   // new users need approval
	RegMaxPerIPDay   int                    `json:"registration.max_per_ip_per_day"` // 0 off
	RegPerSec        float64                `json:"registration.per_sec"`            // per IP registration rate
	SiteName         string                 `json:"site.name"`                       // display name
	SiteDescription  string                 `json:"site.description"`                // homepage description, <= 280
	Announcement     string                 `json:"site.announcement_text"`          // banner text, <= 500
	AnnouncementLvl  string                 `json:"site.announcement_level"`         // info or warn
	TermsURL         string                 `json:"site.terms_url"`                  // footer link
	PrivacyURL       string                 `json:"site.privacy_url"`                // footer link
	Contact          string                 `json:"site.contact"`                    // footer link
	ShowBanReason    bool                   `json:"site.show_ban_reason"`            // show reason on suspended page
	Maintenance      bool                   `json:"maintenance.enabled"`             // read only API while on
	MaintenanceMsg   string                 `json:"maintenance.message"`             // banner and 503 message
	QuotaDefaultTier string                 `json:"quota.default_tier"`              // default tier name
	QuotaTiers       map[string]config.Tier `json:"quota.tiers"`                     // full tier map override
	TokenMaxTTL      config.Duration        `json:"token.max_ttl"`                   // max token lifetime
	TokenDefaultTTL  config.Duration        `json:"token.default_ttl"`               // create form preselect
	TokenMaxPerUser  int                    `json:"token.max_per_user"`              // per-user token cap
	LoginPerMin      float64                `json:"web.login_per_min"`               // login rate per IP
	FailedAuthPerSec float64                `json:"auth.failed_auth_per_sec"`        // failed auth rate per IP
	SessionIdle      config.Duration        `json:"web.session_idle"`                // idle session timeout
	SessionAbsolute  config.Duration        `json:"web.session_absolute"`            // absolute session timeout
}

// Defaults builds Values from the file config.
func Defaults(cfg *config.Config) Values {
	return Values{
		RegMode: cfg.Registration.Mode, RegApproval: cfg.Registration.RequireApproval,
		RegMaxPerIPDay: cfg.Registration.MaxPerIPPerDay, RegPerSec: cfg.Registration.PerSec,
		SiteName: cfg.Web.InstanceName, SiteDescription: cfg.Web.Description,
		TermsURL: cfg.Web.TermsURL, PrivacyURL: cfg.Web.PrivacyURL, Contact: cfg.Web.Contact,
		QuotaDefaultTier: cfg.Quota.DefaultTier, QuotaTiers: cfg.Quota.Tiers,
		TokenMaxTTL: cfg.Auth.Token.MaxTTL, TokenDefaultTTL: cfg.Auth.Token.DefaultTTL,
		TokenMaxPerUser: cfg.Auth.Token.MaxPerUser,
		LoginPerMin:     cfg.Web.LoginPerMin, FailedAuthPerSec: cfg.Auth.FailedAuthPerSec,
		SessionIdle: cfg.Web.Session.Idle, SessionAbsolute: cfg.Web.Session.Absolute,
	}
}

// Field describes one setting for the admin form.
type Field struct {
	Key, Type, Label, Help string
	Enum                   []string
	Min, Max               float64
}

// Schema lists every key for the settings UI.
func Schema() []Field {
	return []Field{
		{Key: "registration.mode", Type: "enum", Label: "Registration mode", Enum: []string{"closed", "invite", "open"}},
		{Key: "registration.require_approval", Type: "bool", Label: "Require approval"},
		{Key: "registration.max_per_ip_per_day", Type: "int", Label: "Registrations per IP per day", Min: 0},
		{Key: "registration.per_sec", Type: "float", Label: "Registrations per second per IP", Min: 0},
		{Key: "site.name", Type: "string", Label: "Site name"},
		{Key: "site.description", Type: "string", Label: "Description", Max: 280},
		{Key: "site.announcement_text", Type: "string", Label: "Announcement", Max: 500},
		{Key: "site.announcement_level", Type: "enum", Label: "Announcement level", Enum: []string{"info", "warn"}},
		{Key: "site.terms_url", Type: "url", Label: "Terms URL"},
		{Key: "site.privacy_url", Type: "url", Label: "Privacy URL"},
		{Key: "site.contact", Type: "url", Label: "Contact"},
		{Key: "site.show_ban_reason", Type: "bool", Label: "Show ban reason"},
		{Key: "maintenance.enabled", Type: "bool", Label: "Maintenance mode"},
		{Key: "maintenance.message", Type: "string", Label: "Maintenance message"},
		{Key: "quota.default_tier", Type: "string", Label: "Default tier"},
		{Key: "quota.tiers", Type: "tiers", Label: "Tier map"},
		{Key: "token.max_ttl", Type: "duration", Label: "Token max TTL"},
		{Key: "token.default_ttl", Type: "duration", Label: "Token default TTL"},
		{Key: "token.max_per_user", Type: "int", Label: "Tokens per user", Min: 0},
		{Key: "web.login_per_min", Type: "float", Label: "Logins per minute per IP", Min: 0},
		{Key: "auth.failed_auth_per_sec", Type: "float", Label: "Failed auth per second per IP", Min: 0},
		{Key: "web.session_idle", Type: "duration", Label: "Session idle timeout"},
		{Key: "web.session_absolute", Type: "duration", Label: "Session absolute timeout"},
	}
}

var errBad = func(k string) error { return fmt.Errorf("settings: invalid %s", k) }

func validLink(v string) bool {
	if v == "" {
		return true
	}
	if strings.HasPrefix(v, "/") {
		return true
	}
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "https" || u.Scheme == "mailto")
}

// validate checks a decoded Values value for one key.
func validate(v Values) error {
	switch v.RegMode {
	case "closed", "invite", "open":
	default:
		return errBad("registration.mode")
	}
	if v.RegMaxPerIPDay < 0 || v.RegPerSec < 0 || v.TokenMaxPerUser < 0 ||
		v.LoginPerMin < 0 || v.FailedAuthPerSec < 0 {
		return errBad("negative")
	}
	if len(v.SiteDescription) > 280 || len(v.Announcement) > 500 {
		return errBad("too long")
	}
	switch v.AnnouncementLvl {
	case "", "info", "warn":
	default:
		return errBad("announcement_level")
	}
	for _, u := range []string{v.TermsURL, v.PrivacyURL, v.Contact} {
		if !validLink(u) {
			return errBad("url")
		}
	}
	if v.QuotaTiers != nil {
		if _, ok := v.QuotaTiers[v.QuotaDefaultTier]; !ok && v.QuotaDefaultTier != "" {
			return errBad("quota.default_tier missing")
		}
		for name, t := range v.QuotaTiers {
			if err := validateTier(name, t); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTier(name string, t config.Tier) error {
	if name == "" || t.QuotaBytes < 0 || t.MaxSlots < 0 {
		return errBad("quota.tiers")
	}
	return nil
}

// AuditSink records one audit event per changed key.
type AuditSink interface {
	Record(ctx context.Context, e meta.AuditEvent)
}

// Change is one applied override.
type Change struct {
	Key       string
	Old, New  json.RawMessage
	UpdatedBy string
}

// Override describes a persisted override row.
type Override struct {
	Key, UpdatedBy string
	UpdatedAt      time.Time
}

// Manager serves live settings with overrides persisted in the store.
type Manager struct {
	store meta.Store
	clock func() time.Time
	// Sink receives one audit event per changed key.
	Sink AuditSink
	cfg  *config.Config

	cur          atomic.Pointer[Values]
	mu           sync.Mutex
	subs         []func(Values, Values)
	stop         chan struct{}
	done         chan struct{}
	over         map[string]meta.SettingRow
	RefreshEvery time.Duration
}

// New builds a manager; clock may be nil.
func New(store meta.Store, cfg *config.Config, clock func() time.Time) *Manager {
	if clock == nil {
		clock = time.Now
	}
	m := &Manager{store: store, cfg: cfg, clock: clock, Sink: nil,
		stop: make(chan struct{}), done: make(chan struct{}), RefreshEvery: 15 * time.Second}
	d := Defaults(cfg)
	m.cur.Store(&d)
	return m
}

// Effective returns the live values, lock free.
func (m *Manager) Effective() Values { return *m.cur.Load() }

// Subscribe registers a change listener.
func (m *Manager) Subscribe(fn func(old, new Values)) {
	m.mu.Lock()
	m.subs = append(m.subs, fn)
	m.mu.Unlock()
}

func (m *Manager) notify(old, new Values) {
	m.mu.Lock()
	subs := append([]func(Values, Values){}, m.subs...)
	m.mu.Unlock()
	for _, f := range subs {
		f(old, new)
	}
}

func (m *Manager) merged() Values {
	base := Defaults(m.cfg)
	raw := m.raw()
	if err := json.Unmarshal(raw, &base); err == nil {
		return base
	}
	return base
}

func (m *Manager) raw() json.RawMessage {
	var top map[string]json.RawMessage
	base, _ := json.Marshal(Defaults(m.cfg))
	_ = json.Unmarshal(base, &top)
	for k, r := range m.over {
		top[k] = json.RawMessage(r.Value)
	}
	out, _ := json.Marshal(top)
	return out
}

// Load reads overrides and applies them.
func (m *Manager) Load(ctx context.Context) error {
	rows, err := m.store.GetSettings(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.over = rows
	v := m.merged()
	old := *m.cur.Load()
	m.cur.Store(&v)
	m.mu.Unlock()
	if !valuesEqual(old, v) {
		m.notify(old, v)
	}
	return nil
}

func valuesEqual(a, b Values) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

// Update validates the whole patch before persisting anything. A value
// equal to the file default clears the override.
func (m *Manager) Update(ctx context.Context, actor string, patch map[string]json.RawMessage) ([]Change, error) {
	if len(patch) == 0 {
		return nil, nil
	}
	// merge patch over current to validate the result
	cur := m.raw()
	var top map[string]json.RawMessage
	_ = json.Unmarshal(cur, &top)
	known := map[string]bool{}
	for _, f := range Schema() {
		known[f.Key] = true
	}
	for k, v := range patch {
		if !known[k] {
			return nil, errBad(k)
		}
		top[k] = v
	}
	merged, _ := json.Marshal(top)
	var nv Values
	if err := json.Unmarshal(merged, &nv); err != nil {
		return nil, errBad("patch")
	}
	if err := validate(nv); err != nil {
		return nil, err
	}
	// defaults for clearing
	def, _ := json.Marshal(Defaults(m.cfg))
	var dtop map[string]json.RawMessage
	_ = json.Unmarshal(def, &dtop)
	old := *m.cur.Load()
	var changes []Change
	for k, v := range patch {
		oldRaw := top[k]
		if oldRaw == nil {
			oldRaw = dtop[k]
		}
		// equal to file default clears the override
		isDef := string(v) == string(dtop[k])
		var err error
		if isDef {
			err = m.store.DeleteSetting(ctx, k)
			delete(m.over, k)
		} else {
			err = m.store.PutSetting(ctx, k, string(v), actor)
			m.over[k] = meta.SettingRow{Key: k, Value: string(v), UpdatedAt: m.clock(), UpdatedBy: actor}
		}
		if err != nil {
			return nil, err
		}
		changes = append(changes, Change{Key: k, Old: oldRaw, New: v, UpdatedBy: actor})
		if m.Sink != nil {
			id, _ := meta.NewID(m.clock())
			m.Sink.Record(ctx, meta.AuditEvent{ID: id, At: m.clock(), ActorID: actor,
				Action: "settings.change", TargetType: "setting", TargetID: k,
				Detail: fmt.Sprintf(`{"old":%s,"new":%s}`, oldRaw, v)})
		}
	}
	v := m.merged()
	m.cur.Store(&v)
	m.notify(old, v)
	return changes, nil
}

// Reset clears one override.
func (m *Manager) Reset(ctx context.Context, actor, key string) error {
	if _, ok := m.over[key]; !ok {
		return nil
	}
	if err := m.store.DeleteSetting(ctx, key); err != nil {
		return err
	}
	old := *m.cur.Load()
	delete(m.over, key)
	v := m.merged()
	m.cur.Store(&v)
	if m.Sink != nil {
		id, _ := meta.NewID(m.clock())
		m.Sink.Record(ctx, meta.AuditEvent{ID: id, At: m.clock(), ActorID: actor,
			Action: "settings.reset", TargetType: "setting", TargetID: key})
	}
	m.notify(old, v)
	return nil
}

// Overrides lists persisted overrides.
func (m *Manager) Overrides() []Override {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Override, 0, len(m.over))
	for _, r := range m.over {
		out = append(out, Override{Key: r.Key, UpdatedBy: r.UpdatedBy, UpdatedAt: r.UpdatedAt})
	}
	return out
}

// SetFileConfig applies a file reload: defaults change, overrides win.
func (m *Manager) SetFileConfig(cfg *config.Config) {
	m.mu.Lock()
	m.cfg = cfg
	v := m.merged()
	old := *m.cur.Load()
	m.cur.Store(&v)
	m.mu.Unlock()
	if !valuesEqual(old, v) {
		m.notify(old, v)
	}
}

// Close stops the refresh loop.
func (m *Manager) Close() {
	close(m.stop)
	<-m.done
}

// Start runs the 15 second convergence loop.
func (m *Manager) Start() {
	go func() {
		defer close(m.done)
		t := time.NewTicker(m.RefreshEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = m.Load(context.Background())
			case <-m.stop:
				return
			}
		}
	}()
}
