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
	GetToken(ctx context.Context, id string) (Token, error)
	TouchToken(ctx context.Context, id string, at time.Time) error
	ListTokens(ctx context.Context, userID string) ([]Token, error)
	RevokeToken(ctx context.Context, id string) error

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
	ID         string
	UserID     string
	SecretHash [32]byte
	Name       string
	Scopes     []string
	Apps       []string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
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
