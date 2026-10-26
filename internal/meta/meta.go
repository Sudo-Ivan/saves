// SPDX-License-Identifier: 0BSD

// Package meta defines the metadata store: users, tokens, slots,
// snapshots, chunk and manifest reference accounting, quota
// reservations, leases, and fsck. Drivers are sqlite and postgres,
// registered from their packages and selected by meta.Open.
//
// Accounting model: a chunk row exists per (user, hash) with a state of
// reserved, stored, or deleting. Reserved bytes count in usage.reserved,
// stored bytes with refcount > 0 count in usage.used. Begin creates a
// reserved row plus a snapshot_chunks reference; MarkChunkStored moves
// reserved to used; dropping the last reference frees the bytes
// immediately and stamps zero_ref_since, while the row and any blob stay
// until the GC grace period lapses.
//
// GC protocol: GC lists zero-ref rows older than the grace period. For
// each it marks the row deleting inside a transaction (only if the
// refcount is still 0), deletes the blob, then calls DeleteChunkRow
// which re-checks refcount == 0 in the same transaction. A Begin that
// references a deleting chunk flips it back to reserved and counts it as
// missing, so the client re-uploads the blob; DeleteChunkRow then finds
// refcount > 0 and keeps the row. If the blob is already gone, the
// upload recreates it. If the row is deleted between blob delete and a
// later Begin, Begin simply creates a fresh reserved row. A crash
// between blob delete and row delete leaves a deleting row that
// UnreferencedChunks returns again (deleting rows are included), so the
// next GC cycle completes the delete; the blob delete is idempotent.
//
// Shared reservations: a chunk reserved by another pending snapshot of
// the same user counts as missing for a new Begin (the client must
// upload it once, the PUT is idempotent) but its bytes are charged to
// reserved only once, when the reserved row is first created. When one
// pending snapshot aborts or expires while another still references the
// chunk, the refcount keeps the row alive; the reserved bytes are
// released only when the last reference drops.
package meta

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Store is the metadata interface both drivers implement.
type Store interface {
	Migrate(ctx context.Context) error
	Ping(ctx context.Context) error
	Close() error

	// UpsertUser returns the user for subject, creating it with tier.
	UpsertUser(ctx context.Context, subject, tier string) (u User, created bool, err error)
	GetUser(ctx context.Context, id string) (User, error)
	GetUserBySubject(ctx context.Context, subject string) (User, error)
	ListUsers(ctx context.Context, after string, limit int) ([]User, error)
	UpdateUser(ctx context.Context, id string, p UserPatch) (User, error)
	// DeleteUser soft deletes: disables the user and stamps deleted_at.
	DeleteUser(ctx context.Context, id string) error

	CreateToken(ctx context.Context, t Token) error
	UpdateToken(ctx context.Context, id string, p TokenPatch) error
	// Token audit and usage.
	InsertTokenEvent(ctx context.Context, e TokenEvent) error
	UpsertTokenUsage(ctx context.Context, b []UsageRow) ([]UsagePair, error)
	ListTokenEvents(ctx context.Context, tokenID, kind, cursor string, limit int) ([]TokenEvent, string, error)
	TokenStats(ctx context.Context, tokenID string) (TokenStats, error)
	PurgeTokenAudit(ctx context.Context, before time.Time) error
	// Admin settings, invites, moderation, audit and stats.
	GetSettings(ctx context.Context) (map[string]SettingRow, error)
	PutSetting(ctx context.Context, key, valueJSON, actor string) error
	DeleteSetting(ctx context.Context, key string) error
	CreateInvite(ctx context.Context, in Invite) error
	ListInvites(ctx context.Context) ([]Invite, error)
	RevokeInvite(ctx context.Context, id string) error
	ConsumeInvite(ctx context.Context, codeHash [32]byte, userID, ip string) error
	SetUserStatus(ctx context.Context, st UserStatus) error
	GetUserStatus(ctx context.Context, userID string) (UserStatus, error)
	ClearUserStatus(ctx context.Context, userID string) error
	ListUserStatuses(ctx context.Context, state string) ([]UserStatus, error)
	ExpireBans(ctx context.Context, now time.Time) ([]string, error)
	AddIPBlock(ctx context.Context, b IPBlock) error
	ListIPBlocks(ctx context.Context) ([]IPBlock, error)
	DeleteIPBlock(ctx context.Context, id string) error
	PurgeExpiredIPBlocks(ctx context.Context, now time.Time) error
	InsertAudit(ctx context.Context, ev []AuditEvent) error
	ListAudit(ctx context.Context, f AuditFilter, cursor string, limit int) ([]AuditEvent, string, error)
	PurgeAudit(ctx context.Context, before time.Time) error
	AddStats(ctx context.Context, d []StatsDelta) error
	SetStatsGauges(ctx context.Context, day int, storageBytes, usersTotal, activeUsers int64) error
	TouchActivity(ctx context.Context, ud []UserDay) error
	StatsSeries(ctx context.Context, fromDay, toDay int) ([]StatsRow, error)
	PurgeStats(ctx context.Context, beforeDay int) error
	ListUsersAdmin(ctx context.Context, f UserFilter, offset, limit int) ([]AdminUserRow, int, error)
	AdminTotals(ctx context.Context) (AdminTotals, error)
	TopUsersByStorage(ctx context.Context, n int) ([]AdminUserRow, error)
	TopApps(ctx context.Context, n int) ([]AppBytes, error)
	// Per-app byte totals for visualization.
	AppBytes(ctx context.Context, userID string) ([]AppBytes, error)
	// Daily snapshot activity for visualization.
	SnapshotActivity(ctx context.Context, userID string, days int) ([]DayActivity, error)
	// Bandwidth accounting.
	AddBandwidth(ctx context.Context, rows []BandwidthRow) error
	BandwidthUsage(ctx context.Context, userID string, fromDay, toDay int) ([]BandwidthRow, error)
	PurgeBandwidth(ctx context.Context, beforeDay int) error
	GetToken(ctx context.Context, id string) (Token, error)
	TouchToken(ctx context.Context, id string, at time.Time) error
	ListTokens(ctx context.Context, userID string) ([]Token, error)
	RevokeToken(ctx context.Context, id string) error

	// Vault header record, one per user.
	GetVault(ctx context.Context, userID string) (VaultRecord, error)
	PutVault(ctx context.Context, userID string, header []byte, kid string, ifVersion *int64) (int64, error)
	DeleteVault(ctx context.Context, userID string) error

	// BeginSnapshot atomically upserts the slot, inserts the pending
	// snapshot plus chunk references, computes the missing set, and
	// reserves quota.
	BeginSnapshot(ctx context.Context, p BeginParams) (BeginResult, error)
	// MarkChunkStored records a stored chunk for a pending snapshot.
	MarkChunkStored(ctx context.Context, userID, snapshotID string, h api.Hash, size int64) error
	// CommitSnapshot compares and swaps the slot head and applies
	// retention.
	CommitSnapshot(ctx context.Context, userID, snapshotID string, o CommitOptions) (CommitResult, error)
	AbortSnapshot(ctx context.Context, userID, snapshotID string) error
	ExpirePending(ctx context.Context, now time.Time, limit int) (int, error)
	GetSnapshot(ctx context.Context, userID, app, slot, id string) (Snapshot, error)
	ListSnapshots(ctx context.Context, userID, app, slot, cursor string, limit int) ([]Snapshot, string, error)
	DeleteSnapshot(ctx context.Context, userID, app, slot, id string) error

	ListApps(ctx context.Context, userID string) ([]AppSummary, error)
	ListSlots(ctx context.Context, userID, app string) ([]Slot, error)
	GetSlot(ctx context.Context, userID, app, slot string) (Slot, error)
	DeleteSlot(ctx context.Context, userID, app, slot string) error
	Usage(ctx context.Context, userID string) (Usage, error)

	// UnreferencedChunks returns zero-ref rows older than olderThan,
	// including rows stuck in deleting after a crash.
	UnreferencedChunks(ctx context.Context, olderThan time.Time, limit int) ([]ChunkRow, error)
	// MarkDeleting flips a zero-ref chunk row to deleting so the GC can
	// delete the blob then call DeleteChunkRow. Returns false when the
	// row is still referenced.
	MarkDeleting(ctx context.Context, userID string, h api.Hash) (bool, error)
	// DeleteChunkRow deletes the row only if its refcount is still 0.
	DeleteChunkRow(ctx context.Context, userID string, h api.Hash) (bool, error)
	UnreferencedManifests(ctx context.Context, olderThan time.Time, limit int) ([]ManifestRow, error)
	DeleteManifestRow(ctx context.Context, userID string, h api.Hash) (bool, error)
	PurgedUsers(ctx context.Context, limit int) ([]User, error)
	FinishPurge(ctx context.Context, userID string) error
	AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error)
	Fsck(ctx context.Context, repair bool) (FsckReport, error)

	// Web credentials, recovery codes, and browser sessions.
	// GetCredentialByUsername matches the stored lowercase username.
	GetCredentialByUsername(ctx context.Context, username string) (WebCredential, error)
	GetCredential(ctx context.Context, userID string) (WebCredential, error)
	// CreateCredential fails with ErrExists on a username clash.
	CreateCredential(ctx context.Context, c WebCredential) error
	UpdateCredential(ctx context.Context, userID string, p CredentialPatch) error
	// SetRecoveryCodes replaces the whole set for a user.
	SetRecoveryCodes(ctx context.Context, userID string, hashes [][32]byte) error
	// ConsumeRecoveryCode atomically marks one code used and reports
	// the remaining count; ErrNotFound when the code is unknown or
	// already used.
	ConsumeRecoveryCode(ctx context.Context, userID string, hash [32]byte) (remaining int, err error)
	// AdvanceTOTPStep is an atomic compare and set: it stores step only
	// when step is greater than the stored one, reporting success.
	AdvanceTOTPStep(ctx context.Context, userID string, step int64) (bool, error)

	CreateWebSession(ctx context.Context, ws WebSession) error
	GetWebSession(ctx context.Context, idHash [32]byte) (WebSession, error)
	TouchWebSession(ctx context.Context, idHash [32]byte, at time.Time) error
	BumpWebSessionAttempts(ctx context.Context, idHash [32]byte) (int, error)
	DeleteWebSession(ctx context.Context, idHash [32]byte) error
	// DeleteUserSessions drops every session of a user, or all but
	// except when except is non-nil.
	DeleteUserSessions(ctx context.Context, userID string, except *[32]byte) (int, error)
	ListWebSessions(ctx context.Context, userID string) ([]WebSession, error)
	PurgeWebSessions(ctx context.Context, now time.Time) (int, error)
}

// Options configures a store instance.
type Options struct {
	// Clock supplies the current time; nil means time.Now.
	Clock func() time.Time
}

// User is a registered principal.
type User struct {
	ID         string
	Subject    string
	Tier       string
	QuotaBytes *int64
	Disabled   bool
	DeletedAt  *time.Time
	CreatedAt  time.Time
}

// Optional is a tri-state patch field: unset leaves the column, set with
// Null clears it, set with a value assigns it.
type Optional[T any] struct {
	Set   bool
	Null  bool
	Value T
}

// UserPatch updates mutable user columns.
type UserPatch struct {
	Tier       *string
	QuotaBytes *Optional[int64]
	Disabled   *bool
}

// Token is an API credential. Only the SHA-256 of the secret is stored.
type Token struct {
	ID           string
	UserID       string
	SecretHash   [32]byte
	Name         string
	Scopes       []string
	Apps         []string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	RevokedAt    *time.Time
	LastUsedAt   *time.Time
	AllowedCIDRs []string
}

// Snapshot is one version of a slot.
type Snapshot struct {
	ID           string
	UserID       string
	App          string
	Slot         string
	ParentID     string
	Device       string
	Label        string
	State        string
	ManifestHash api.Hash
	ManifestSize int64
	TotalBytes   int64
	FileCount    int
	CreatedAt    time.Time
	CommittedAt  *time.Time
	ExpiresAt    *time.Time
}

// Snapshot states.
const (
	StatePending   = "pending"
	StateCommitted = "committed"
)

// Chunk states.
const (
	ChunkReserved = "reserved"
	ChunkStored   = "stored"
	ChunkDeleting = "deleting"
)

// BeginParams carries one manifest's worth of chunk references.
type BeginParams struct {
	UserID       string
	App          string
	Slot         string
	ParentID     string
	Device       string
	Label        string
	ManifestHash api.Hash
	ManifestSize int64
	TotalBytes   int64
	FileCount    int
	Chunks       []api.ChunkRef
	Limits       BeginLimits
}

// BeginLimits bounds a Begin call.
type BeginLimits struct {
	QuotaBytes          int64
	MaxSlots            int
	MaxPendingSnapshots int
	ExpiresAt           time.Time
}

// BeginResult is a created pending snapshot and its missing chunks.
type BeginResult struct {
	Snapshot Snapshot
	Missing  []api.Hash
}

// CommitOptions controls the head compare and swap and retention.
type CommitOptions struct {
	ExpectedHead string
	Force        bool
	KeepLast     int
	MaxAge       time.Duration
}

// CommitResult is the committed snapshot plus pruned snapshot ids.
type CommitResult struct {
	Snapshot Snapshot
	Pruned   []string
}

// Slot is a save profile or world with a head pointer.
type Slot struct {
	UserID         string
	App            string
	Name           string
	HeadSnapshotID string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AppSummary is one app of a user.
type AppSummary struct {
	App       string
	Slots     int
	Snapshots int
}

// Usage is the quota accounting view of a user.
type Usage struct {
	UsedBytes     int64
	ReservedBytes int64
	QuotaBytes    int64
	Slots         int
	Snapshots     int
}

// ChunkRow is a chunk accounting row.
type ChunkRow struct {
	UserID       string
	Hash         api.Hash
	Size         int64
	State        string
	ZeroRefSince *time.Time
}

// ManifestRow is a manifest accounting row.
type ManifestRow struct {
	UserID       string
	Hash         api.Hash
	Size         int64
	ZeroRefSince *time.Time
}

// FsckReport summarizes a consistency check.
type FsckReport struct {
	Issues     []string
	Repaired   bool
	Refcounts  int
	UsageFixed int
	OrphanRefs int
}

// WebCredential holds the web sign-in data of a user.
type WebCredential struct {
	UserID       string
	Username     string // stored lowercase, unique
	PasswordHash string // PHC string, empty for OIDC only accounts
	Admin        bool
	MustChange   bool
	TOTPSecret   []byte // sealed, nil when unset
	TOTPEnabled  bool
	TOTPLastStep int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CredentialPatch updates the mutable credential columns. A nil field
// leaves the column untouched.
type CredentialPatch struct {
	PasswordHash *string
	MustChange   *bool
	Admin        *bool
	TOTPEnabled  *bool
	// TOTPSecret nil leaves it, empty slice clears it, non-empty stores
	// the new sealed secret.
	TOTPSecret *[]byte
	// TOTPLastStep resets the replay counter when non-nil.
	TOTPLastStep *int64
}

// Web session kinds.
const (
	SessionPending = "pending"
	SessionFull    = "full"
)

// Web session methods.
const (
	SessionMethodPassword = "password"
	SessionMethodOIDC     = "oidc"
)

// WebSession is one browser session. Only the SHA-256 of the cookie
// value is stored.
type WebSession struct {
	IDHash     [32]byte
	UserID     string
	Kind       string
	Method     string
	Admin      bool
	CSRF       [32]byte
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IP         string
	UserAgent  string
	Attempts   int
}

// VaultRecord is one per-user vault header.
type VaultRecord struct {
	Header  []byte
	KID     string
	Version int64
}

// ErrVersionMismatch fires when an If-Match version is stale.
var ErrVersionMismatch = errors.New("meta: vault version mismatch")

var (
	ErrNotFound     = errors.New("meta: not found")
	ErrNotExpected  = errors.New("meta: chunk not expected")
	ErrDisabled     = errors.New("meta: user disabled")
	ErrExists       = errors.New("meta: already exists")
	ErrPendingLimit = errors.New("meta: pending snapshot limit")
	// ErrContended is returned internally to trigger a transaction retry.
	ErrContended = errors.New("meta: contention, retry")
	ErrSlotLimit = errors.New("meta: slot limit")
)

// ConflictError reports a head compare and swap failure.
type ConflictError struct {
	Head Snapshot
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("meta: head conflict, head is %s", e.Head.ID)
}

// QuotaError reports a quota rejection.
type QuotaError struct {
	Used     int64
	Reserved int64
	Limit    int64
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("meta: quota exceeded used=%d reserved=%d limit=%d", e.Used, e.Reserved, e.Limit)
}

// IncompleteError reports a commit with chunks still missing.
type IncompleteError struct {
	Missing int
}

func (e *IncompleteError) Error() string {
	return fmt.Sprintf("meta: snapshot incomplete, %d chunks missing", e.Missing)
}

// NewID returns a time sortable 26 character ULID: 48 bits of unix
// milliseconds plus 80 bits of randomness, Crockford base32.
func NewID(now time.Time) (string, error) {
	var b [16]byte
	ms := uint64(now.UnixMilli())
	b[0] = byte(ms >> 40) // #nosec G115 -- intentional truncation to byte
	b[1] = byte(ms >> 32) // #nosec G115 -- intentional truncation to byte
	b[2] = byte(ms >> 24) // #nosec G115 -- intentional truncation to byte
	b[3] = byte(ms >> 16) // #nosec G115 -- intentional truncation to byte
	b[4] = byte(ms >> 8)  // #nosec G115 -- intentional truncation to byte
	b[5] = byte(ms)       // #nosec G115 -- intentional truncation to byte
	if _, err := rand.Read(b[6:]); err != nil {
		return "", err
	}
	return encodeULID(b[:]), nil
}

// encodeULID Crockford base32 encodes 16 bytes as 26 chars.
func encodeULID(b []byte) string {
	const enc = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var out [26]byte
	for i := 0; i < 26; i++ {
		bitPos := i * 5
		var v uint
		for j := 0; j < 5 && bitPos+j < 128; j++ {
			if b[(bitPos+j)/8]&(1<<(7-uint((bitPos+j)%8))) != 0 {
				v |= 1 << (4 - uint(j))
			}
		}
		out[i] = enc[v]
	}
	return string(out[:])
}

// EncodeCursor packs the last seen ordering key.
func EncodeCursor(createdNS int64, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(createdNS, 10) + ":" + id))
}

// DecodeCursor unpacks a cursor.
func DecodeCursor(c string) (int64, string, error) {
	if c == "" {
		return 0, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, "", fmt.Errorf("meta: bad cursor")
	}
	ns, id, ok := strings.Cut(string(raw), ":")
	if !ok || id == "" {
		return 0, "", fmt.Errorf("meta: bad cursor")
	}
	v, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("meta: bad cursor")
	}
	return v, id, nil
}

// Opener builds a Store from a driver config.
type Opener func(ctx context.Context, dsn string, opt Options) (Store, error)

var drivers = map[string]Opener{}

// RegisterDriver registers a backend opener, called by driver init.
func RegisterDriver(name string, o Opener) {
	drivers[name] = o
}

// Open selects a driver by name. sqlite takes a file path, postgres a
// DSN.
func Open(ctx context.Context, driver, dsn string, opt Options) (Store, error) {
	o, ok := drivers[driver]
	if !ok {
		return nil, fmt.Errorf("meta: driver %q not registered (import its package)", driver)
	}
	return o(ctx, dsn, opt)
}

// TokenPatch edits the mutable token fields. Nil leaves a field alone.
type TokenPatch struct {
	Name      *string
	ExpiresAt **time.Time
	CIDRs     *[]string
}

// TokenEvent is one audit row.
type TokenEvent struct {
	ID, TokenID, UserID, Kind, IP, ActorID, UserAgent, RequestID, Detail string
	At                                                                   time.Time
}

// UsageRow is one token_usage upsert row.
type UsageRow struct {
	TokenID, IP, UserAgent string
	Bucket                 time.Time
	Requests               int64
	LastSeen               time.Time
}

// IPCount is a top-IP rollup row.
// UsagePair reports a (token, ip) pair that had no usage row before an
// upsert. First is true when the token had no usage rows at all.
type UsagePair struct {
	TokenID, IP string
	First       bool
}

type IPCount struct {
	IP        string
	Requests  int64
	LastSeen  time.Time
	UserAgent string
}

// TokenStats aggregates usage for one token.
type TokenStats struct {
	Total, Last24h, Last7d, Last30d int64
	Daily                           []int64 // last 30 days, zero filled
	UniqueIPs30d                    int64
	TopIPs                          []IPCount
	Denied                          map[string]int64
	FirstUse, LastUse               *time.Time
}

// AppBytes totals logical head size per app.
type AppBytes struct {
	App       string
	Slots     int
	Snapshots int
	Bytes     int64
}

// DayActivity is one day of committed snapshot volume.
type DayActivity struct {
	Day       time.Time
	Snapshots int
	Bytes     int64
}

// BandwidthRow is one day of upload and download bytes.
type BandwidthRow struct {
	UserID   string
	Day      int
	Up, Down int64
}

// BandwidthDay converts a time to the YYYYMMDD day key.
func BandwidthDay(t time.Time) int {
	t = t.UTC()
	return t.Year()*10000 + int(t.Month())*100 + t.Day()
}

// ErrInviteInvalid is the single failure for invite consumption.
var ErrInviteInvalid = errors.New("meta: invite invalid")

// SettingRow is one persisted settings override.
type SettingRow struct {
	Key, Value, UpdatedBy string
	UpdatedAt             time.Time
}

// Invite is one registration invite.
type Invite struct {
	ID, CodePrefix, Label, CreatedBy string
	CodeHash                         [32]byte
	MaxUses, Uses                    int
	ExpiresAt, CreatedAt, RevokedAt  *time.Time
	Status                           string
}

// UserStatus is a moderation state (pending or banned).
type UserStatus struct {
	UserID, State, Reason, By string
	At                        time.Time
	Until                     *time.Time
}

// IPBlock is one blocked address range.
type IPBlock struct {
	ID, CIDR, Reason, CreatedBy string
	CreatedAt                   time.Time
	ExpiresAt                   *time.Time
}

// AuditEvent is one admin or auth audit row.
type AuditEvent struct {
	ID                          string
	At                          time.Time
	ActorID, ActorLabel, Action string
	TargetType, TargetID, IP    string
	Detail, RequestID           string
}

// AuditFilter narrows ListAudit.
type AuditFilter struct {
	Action, ActorID, TargetID, Query string
	From, To                         time.Time
}

// StatsDelta adds counters for one day.
type StatsDelta struct {
	Day                                                  int
	Signups, LoginsOK, LoginsFailed, Requests, Errors5xx int64
	BytesIn, BytesOut, Snapshots                         int64
}

// StatsRow is one stats_daily row.
type StatsRow struct {
	Day                                                       int
	Signups, LoginsOK, LoginsFailed, Requests, Errors5xx      int64
	BytesIn, BytesOut, Snapshots, ActiveUsers, Storage, Users int64
}

// UserDay marks a user active on a day.
type UserDay struct {
	UserID string
	Day    int
}

// UserFilter narrows ListUsersAdmin.
type UserFilter struct {
	Query, State, Tier string
	AdminOnly          bool
	Sort               string
	Desc               bool
}

// AdminUserRow is one admin list row.
type AdminUserRow struct {
	User                                 User
	Username                             string
	WebAdmin, TOTP                       bool
	Status, StatusReason                 string
	UsedBytes, ReservedBytes, QuotaBytes int64
	Snapshots, Slots                     int
	LastActive                           *time.Time
	Tokens, Sessions                     int
}

// AdminTotals aggregates dashboard counters.
type AdminTotals struct {
	Users, Disabled, PendingUsers, Banned, Deleted int64
	UsedBytes, Snapshots, Slots, Apps              int64
	ActiveTokens, ActiveSessions                   int64
	PendingSnapshots                               int64
}
