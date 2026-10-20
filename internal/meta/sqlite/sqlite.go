// SPDX-License-Identifier: 0BSD

// Package sqlite implements meta.Store on embedded SQLite via
// modernc.org/sqlite. All mutations run inside BEGIN IMMEDIATE on a
// single write connection, which serializes quota decisions per user.
// Timestamps are stored as unix nanoseconds, hashes as 32 byte blobs.
package sqlite

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/pkg/api"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migFS embed.FS

func init() {
	meta.RegisterDriver("sqlite", func(ctx context.Context, dsn string, opt meta.Options) (meta.Store, error) {
		return Open(dsn, opt)
	})
}

// Store is the sqlite backend.
type Store struct {
	w     *sql.DB
	r     *sql.DB
	clock func() time.Time
}

var _ meta.Store = (*Store)(nil)

// Open opens the database at path with WAL, busy_timeout, foreign keys,
// and a single writer plus read pool.
func Open(path string, opt meta.Options) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("meta sqlite: %w", err)
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("meta sqlite: %w", err)
	}
	r.SetMaxOpenConns(8)
	s := &Store{w: w, r: r, clock: opt.Clock}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s, nil
}

func (s *Store) now() time.Time { return s.clock() }

func ns(t time.Time) int64 { return t.UnixNano() }
func nsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixNano()
}
func tm(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(0, v.Int64).UTC()
	return &t
}

type q interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// wtx runs fn inside BEGIN IMMEDIATE on the single write connection.
func (s *Store) wtx(ctx context.Context, fn func(q q) error) error {
	for attempt := 0; attempt < 5; attempt++ {
		err := s.wtx1(ctx, fn)
		if !errors.Is(err, meta.ErrContended) {
			return err
		}
	}
	return s.wtx1(ctx, fn)
}

func (s *Store) wtx1(ctx context.Context, fn func(q q) error) error {
	conn, err := s.w.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("meta sqlite: begin: %w", err)
	}
	if err := fn(conn); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("meta sqlite: commit: %w", err)
	}
	return nil
}

// GetVault implements meta.Store.
func (s *Store) GetVault(ctx context.Context, userID string) (meta.VaultRecord, error) {
	var r meta.VaultRecord
	err := s.r.QueryRowContext(ctx,
		"SELECT header, kid, version FROM vault WHERE user_id = ?", userID).
		Scan(&r.Header, &r.KID, &r.Version)
	if err != nil {
		return r, meta.ErrNotFound
	}
	return r, nil
}

// PutVault implements meta.Store.
func (s *Store) PutVault(ctx context.Context, userID string, header []byte, kid string, ifVersion *int64) (int64, error) {
	if len(header) > 8192 {
		return 0, fmt.Errorf("meta: vault header too large")
	}
	now := time.Now().UnixNano()
	if ifVersion == nil {
		_, err := s.w.ExecContext(ctx,
			"INSERT INTO vault (user_id, header, kid, version, updated_at) VALUES (?, ?, ?, 1, ?)",
			userID, header, kid, now)
		if err != nil {
			return 0, meta.ErrVersionMismatch
		}
		return 1, nil
	}
	res, err := s.w.ExecContext(ctx,
		"UPDATE vault SET header = ?, kid = ?, version = version + 1, updated_at = ? WHERE user_id = ? AND version = ?",
		header, kid, now, userID, *ifVersion)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0, meta.ErrVersionMismatch
	}
	return *ifVersion + 1, nil
}

// DeleteVault implements meta.Store.
func (s *Store) DeleteVault(ctx context.Context, userID string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM vault WHERE user_id = ?", userID)
	return err
}

// Migrate applies embedded migrations in order.
func (s *Store) Migrate(ctx context.Context) error {
	var files []string
	if err := fs.WalkDir(migFS, "migrations", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return err
	}); err != nil {
		return err
	}
	sort.Strings(files)
	return s.wtx(ctx, func(q q) error {
		if _, err := q.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
			return err
		}
		var have int
		_ = q.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&have)
		for i, f := range files {
			ver := i + 1
			if ver <= have {
				continue
			}
			data, err := migFS.ReadFile(f)
			if err != nil {
				return err
			}
			if _, err := q.ExecContext(ctx, string(data)); err != nil {
				return fmt.Errorf("meta sqlite: migration %s: %w", f, err)
			}
			if _, err := q.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, ver, ns(s.now())); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) Ping(ctx context.Context) error { return s.r.PingContext(ctx) }

func (s *Store) Close() error {
	_ = s.r.Close()
	return s.w.Close()
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func scanUser(row *sql.Row) (meta.User, error) {
	var u meta.User
	var quota sql.NullInt64
	var deleted, created sql.NullInt64
	var disabled int
	err := row.Scan(&u.ID, &u.Subject, &u.Tier, &quota, &disabled, &deleted, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return u, meta.ErrNotFound
	}
	if err != nil {
		return u, err
	}
	if quota.Valid {
		u.QuotaBytes = &quota.Int64
	}
	u.Disabled = disabled != 0
	u.DeletedAt = tm(deleted)
	u.CreatedAt = time.Unix(0, created.Int64).UTC()
	return u, nil
}

const userCols = `id, subject, tier, quota_bytes, disabled, deleted_at, created_at`

func (s *Store) getUser(ctx context.Context, qq q, where, arg string) (meta.User, error) {
	return scanUser(qq.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE `+where+`=?`, arg))
}

// UpsertUser implements meta.Store.UpsertUser.
func (s *Store) UpsertUser(ctx context.Context, subject, tier string) (meta.User, bool, error) {
	var u meta.User
	var created bool
	err := s.wtx(ctx, func(q q) error {
		id, err := newUserID()
		if err != nil {
			return err
		}
		res, err := q.ExecContext(ctx, `INSERT INTO users(id,subject,tier,created_at) VALUES(?,?,?,?) ON CONFLICT(subject) DO NOTHING`,
			id, subject, tier, ns(s.now()))
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			created = true
		}
		u, err = s.getUser(ctx, q, "subject", subject)
		return err
	})
	return u, created, err
}

func newUserID() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (s *Store) GetUser(ctx context.Context, id string) (meta.User, error) {
	return s.getUser(ctx, s.r, "id", id)
}

func (s *Store) GetUserBySubject(ctx context.Context, subject string) (meta.User, error) {
	return s.getUser(ctx, s.r, "subject", subject)
}

func (s *Store) ListUsers(ctx context.Context, after string, limit int) ([]meta.User, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+userCols+` FROM users WHERE id > ? ORDER BY id LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.User
	for rows.Next() {
		var u meta.User
		var quota, deleted, created sql.NullInt64
		var disabled int
		if err := rows.Scan(&u.ID, &u.Subject, &u.Tier, &quota, &disabled, &deleted, &created); err != nil {
			return nil, err
		}
		if quota.Valid {
			u.QuotaBytes = &quota.Int64
		}
		u.Disabled = disabled != 0
		u.DeletedAt = tm(deleted)
		u.CreatedAt = time.Unix(0, created.Int64).UTC()
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUser(ctx context.Context, id string, p meta.UserPatch) (meta.User, error) {
	var u meta.User
	err := s.wtx(ctx, func(q q) error {
		var err error
		u, err = s.getUser(ctx, q, "id", id)
		if err != nil {
			return err
		}
		if p.Tier != nil {
			u.Tier = *p.Tier
		}
		if p.QuotaBytes != nil && p.QuotaBytes.Set {
			if p.QuotaBytes.Null {
				u.QuotaBytes = nil
			} else {
				v := p.QuotaBytes.Value
				u.QuotaBytes = &v
			}
		}
		if p.Disabled != nil {
			u.Disabled = *p.Disabled
		}
		var quota, dis any
		if u.QuotaBytes != nil {
			quota = *u.QuotaBytes
		}
		if u.Disabled {
			dis = 1
		} else {
			dis = 0
		}
		res, err := q.ExecContext(ctx, `UPDATE users SET tier=?, quota_bytes=?, disabled=? WHERE id=?`,
			u.Tier, quota, dis, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
	return u, err
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.wtx(ctx, func(q q) error {
		res, err := q.ExecContext(ctx, `UPDATE users SET disabled=1, deleted_at=? WHERE id=? AND deleted_at IS NULL`, ns(s.now()), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
}

func scanToken(row *sql.Row) (meta.Token, error) {
	var t meta.Token
	var exp, rev, last sql.NullInt64
	var scopes, apps string
	var created int64
	var sh []byte
	err := row.Scan(&t.ID, &t.UserID, &sh, &t.Name, &scopes, &apps, &created, &exp, &rev, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return t, meta.ErrNotFound
	}
	if err != nil {
		return t, err
	}
	copy(t.SecretHash[:], sh)
	t.CreatedAt = time.Unix(0, created).UTC()
	t.Scopes = splitCSV(scopes)
	t.Apps = splitCSV(apps)
	t.ExpiresAt = tm(exp)
	t.RevokedAt = tm(rev)
	t.LastUsedAt = tm(last)
	return t, nil
}

// #nosec G101 -- column stores a hash, not a credential
const tokenCols = `id, user_id, secret_hash, name, scopes, apps, created_at, expires_at, revoked_at, last_used_at`

func (s *Store) CreateToken(ctx context.Context, t meta.Token) error {
	var created int64
	if t.CreatedAt.IsZero() {
		created = ns(s.now())
	} else {
		created = ns(t.CreatedAt)
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO tokens(`+tokenCols+`) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.UserID, t.SecretHash[:], t.Name, strings.Join(t.Scopes, ","), strings.Join(t.Apps, ","),
		created, nsPtr(t.ExpiresAt), nsPtr(t.RevokedAt), nsPtr(t.LastUsedAt))
	return err
}

func (s *Store) GetToken(ctx context.Context, id string) (meta.Token, error) {
	return scanToken(s.r.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE id=?`, id))
}

func (s *Store) TouchToken(ctx context.Context, id string, at time.Time) error {
	_, err := s.w.ExecContext(ctx, `UPDATE tokens SET last_used_at=? WHERE id=?`, ns(at), id)
	return err
}

func (s *Store) ListTokens(ctx context.Context, userID string) ([]meta.Token, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE user_id=? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.Token
	for rows.Next() {
		var t meta.Token
		var exp, rev, last sql.NullInt64
		var scopes, apps string
		var created int64
		var sh []byte
		if err := rows.Scan(&t.ID, &t.UserID, &sh, &t.Name, &scopes, &apps, &created, &exp, &rev, &last); err != nil {
			return nil, err
		}
		copy(t.SecretHash[:], sh)
		t.CreatedAt = time.Unix(0, created).UTC()
		t.Scopes = splitCSV(scopes)
		t.Apps = splitCSV(apps)
		t.ExpiresAt = tm(exp)
		t.RevokedAt = tm(rev)
		t.LastUsedAt = tm(last)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeToken(ctx context.Context, id string) error {
	res, err := s.w.ExecContext(ctx, `UPDATE tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, ns(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return meta.ErrNotFound
	}
	return nil
}

// lockUsage ensures the usage row exists and returns it. Within a write
// tx this serializes quota decisions for the user.
func lockUsage(ctx context.Context, q q, userID string) (used, reserved int64, err error) {
	if _, err = q.ExecContext(ctx, `INSERT OR IGNORE INTO usage(user_id) VALUES(?)`, userID); err != nil {
		return 0, 0, err
	}
	err = q.QueryRowContext(ctx, `SELECT used_bytes, reserved_bytes FROM usage WHERE user_id=?`, userID).Scan(&used, &reserved)
	return used, reserved, err
}

func (s *Store) BeginSnapshot(ctx context.Context, p meta.BeginParams) (meta.BeginResult, error) {
	var res meta.BeginResult
	err := s.wtx(ctx, func(q q) error {
		u, err := s.getUser(ctx, q, "id", p.UserID)
		if err != nil {
			return err
		}
		if u.Disabled || u.DeletedAt != nil {
			return meta.ErrDisabled
		}
		used, reserved, err := lockUsage(ctx, q, p.UserID)
		if err != nil {
			return err
		}
		var pending int
		if err := q.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM snapshots WHERE user_id=? AND state=?`, p.UserID, meta.StatePending).Scan(&pending); err != nil {
			return err
		}
		if p.Limits.MaxPendingSnapshots > 0 && pending >= p.Limits.MaxPendingSnapshots {
			return meta.ErrPendingLimit
		}
		// Get or create the slot.
		var slotExists bool
		err = q.QueryRowContext(ctx,
			`SELECT 1 FROM slots WHERE user_id=? AND app=? AND name=?`, p.UserID, p.App, p.Slot).Scan(&slotExists)
		switch {
		case err == nil:
			slotExists = true
		case errors.Is(err, sql.ErrNoRows):
			var slots int
			if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM slots WHERE user_id=?`, p.UserID).Scan(&slots); err != nil {
				return err
			}
			if p.Limits.MaxSlots > 0 && slots >= p.Limits.MaxSlots {
				return meta.ErrSlotLimit
			}
		default:
			return err
		}
		// Dedupe chunk refs.
		type ref struct {
			h    api.Hash
			size int64
		}
		seen := map[api.Hash]int64{}
		var uniq []ref
		for _, c := range p.Chunks {
			if prev, ok := seen[c.Hash]; ok {
				if prev != int64(c.Size) {
					return fmt.Errorf("meta: conflicting sizes for chunk %s", c.Hash)
				}
				continue
			}
			seen[c.Hash] = int64(c.Size)
			uniq = append(uniq, ref{h: c.Hash, size: int64(c.Size)})
		}
		// Plan chunk row changes.
		var deltaReserved, deltaUsed int64
		type cplan struct {
			h       api.Hash
			size    int64
			set     string // new state or ""
			insert  bool
			missing bool
		}
		var plans []cplan
		for _, r := range uniq {
			var st string
			var rc, sz int64
			err := q.QueryRowContext(ctx,
				`SELECT state, refcount, size FROM chunks WHERE user_id=? AND hash=?`, p.UserID, r.h[:]).Scan(&st, &rc, &sz)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				plans = append(plans, cplan{h: r.h, size: r.size, insert: true, missing: true})
				deltaReserved += r.size
			case err != nil:
				return err
			case st == meta.ChunkStored:
				plans = append(plans, cplan{h: r.h, size: sz})
				if rc == 0 {
					deltaUsed += sz
				}
			case st == meta.ChunkReserved:
				plans = append(plans, cplan{h: r.h, size: sz, missing: true})
			case st == meta.ChunkDeleting:
				plans = append(plans, cplan{h: r.h, size: sz, set: meta.ChunkReserved, missing: true})
				deltaReserved += sz
			}
		}
		// Manifest row.
		var mrc int64
		var msz int64
		err = q.QueryRowContext(ctx,
			`SELECT refcount, size FROM manifests WHERE user_id=? AND hash=?`, p.UserID, p.ManifestHash[:]).Scan(&mrc, &msz)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			deltaUsed += p.ManifestSize
		case err != nil:
			return err
		case mrc == 0:
			deltaUsed += msz
		}
		quota := p.Limits.QuotaBytes
		if u.QuotaBytes != nil {
			quota = *u.QuotaBytes
		}
		if quota > 0 && used+reserved+deltaUsed+deltaReserved > quota {
			return &meta.QuotaError{Used: used + deltaUsed, Reserved: reserved + deltaReserved, Limit: quota}
		}
		id, err := meta.NewID(s.now())
		if err != nil {
			return err
		}
		var exp any
		if !p.Limits.ExpiresAt.IsZero() {
			exp = ns(p.Limits.ExpiresAt)
		}
		if _, err := q.ExecContext(ctx, `INSERT INTO snapshots(id,user_id,app,slot,parent_id,device,label,state,manifest_hash,manifest_size,total_bytes,file_count,created_at,expires_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, p.UserID, p.App, p.Slot, p.ParentID, p.Device, p.Label, meta.StatePending,
			p.ManifestHash[:], p.ManifestSize, p.TotalBytes, p.FileCount, ns(s.now()), exp); err != nil {
			return err
		}
		if !slotExists {
			if _, err := q.ExecContext(ctx,
				`INSERT INTO slots(user_id,app,name,created_at,updated_at) VALUES(?,?,?,?,?)`,
				p.UserID, p.App, p.Slot, ns(s.now()), ns(s.now())); err != nil {
				return err
			}
		}
		for _, pl := range plans {
			if _, err := q.ExecContext(ctx,
				`INSERT INTO snapshot_chunks(snapshot_id,user_id,hash) VALUES(?,?,?)`, id, p.UserID, pl.h[:]); err != nil {
				return err
			}
			switch {
			case pl.insert:
				if _, err := q.ExecContext(ctx,
					`INSERT INTO chunks(user_id,hash,size,state,refcount,created_at) VALUES(?,?,?,?,1,?)`,
					p.UserID, pl.h[:], pl.size, meta.ChunkReserved, ns(s.now())); err != nil {
					return err
				}
			case pl.set != "":
				ures, err := q.ExecContext(ctx,
					`UPDATE chunks SET state=?, refcount=refcount+1, zero_ref_since=NULL WHERE user_id=? AND hash=?`,
					pl.set, p.UserID, pl.h[:])
				if err != nil {
					return err
				}
				if n, _ := ures.RowsAffected(); n == 0 {
					return meta.ErrContended
				}
			default:
				ures, err := q.ExecContext(ctx,
					`UPDATE chunks SET refcount=refcount+1, zero_ref_since=NULL WHERE user_id=? AND hash=?`,
					p.UserID, pl.h[:])
				if err != nil {
					return err
				}
				if n, _ := ures.RowsAffected(); n == 0 {
					return meta.ErrContended
				}
			}
			if pl.missing {
				res.Missing = append(res.Missing, pl.h)
			}
		}
		if _, err := q.ExecContext(ctx,
			`INSERT INTO manifests(user_id,hash,size,refcount) VALUES(?,?,?,1)
			 ON CONFLICT(user_id,hash) DO UPDATE SET refcount=refcount+1, zero_ref_since=NULL`,
			p.UserID, p.ManifestHash[:], p.ManifestSize); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx,
			`UPDATE usage SET used_bytes=used_bytes+?, reserved_bytes=reserved_bytes+? WHERE user_id=?`,
			deltaUsed, deltaReserved, p.UserID); err != nil {
			return err
		}
		res.Snapshot = meta.Snapshot{
			ID: id, UserID: p.UserID, App: p.App, Slot: p.Slot, ParentID: p.ParentID,
			Device: p.Device, Label: p.Label, State: meta.StatePending,
			ManifestHash: p.ManifestHash, ManifestSize: p.ManifestSize,
			TotalBytes: p.TotalBytes, FileCount: p.FileCount, CreatedAt: s.now(),
		}
		if !p.Limits.ExpiresAt.IsZero() {
			t := p.Limits.ExpiresAt
			res.Snapshot.ExpiresAt = &t
		}
		return nil
	})
	return res, err
}

func (s *Store) MarkChunkStored(ctx context.Context, userID, snapshotID string, h api.Hash, size int64) error {
	return s.wtx(ctx, func(q q) error {
		var st string
		err := q.QueryRowContext(ctx,
			`SELECT state FROM snapshots WHERE id=? AND user_id=?`, snapshotID, userID).Scan(&st)
		if errors.Is(err, sql.ErrNoRows) {
			return meta.ErrNotFound
		}
		if err != nil {
			return err
		}
		if st != meta.StatePending {
			return meta.ErrNotExpected
		}
		var hasRef bool
		err = q.QueryRowContext(ctx,
			`SELECT 1 FROM snapshot_chunks WHERE snapshot_id=? AND hash=?`, snapshotID, h[:]).Scan(&hasRef)
		if errors.Is(err, sql.ErrNoRows) {
			return meta.ErrNotExpected
		}
		if err != nil {
			return err
		}
		var cst string
		var csz int64
		err = q.QueryRowContext(ctx,
			`SELECT state, size FROM chunks WHERE user_id=? AND hash=?`, userID, h[:]).Scan(&cst, &csz)
		if errors.Is(err, sql.ErrNoRows) {
			return meta.ErrNotExpected
		}
		if err != nil {
			return err
		}
		switch cst {
		case meta.ChunkStored:
			return nil // already stored through a shared reservation
		case meta.ChunkReserved:
			if csz != size {
				return fmt.Errorf("meta: chunk size %d, expected %d", size, csz)
			}
			ures, err := q.ExecContext(ctx,
				`UPDATE chunks SET state=? WHERE user_id=? AND hash=? AND state=?`,
				meta.ChunkStored, userID, h[:], meta.ChunkReserved)
			if err != nil {
				return err
			}
			if n, _ := ures.RowsAffected(); n == 0 {
				return nil // lost a race to a shared reservation
			}
			if _, err := q.ExecContext(ctx,
				`UPDATE usage SET used_bytes=used_bytes+?, reserved_bytes=reserved_bytes-? WHERE user_id=?`,
				size, size, userID); err != nil {
				return err
			}
			return nil
		default:
			return meta.ErrNotExpected
		}
	})
}

// release drops every reference of a snapshot and frees its accounting.
// State is read from the decrement statement itself so a concurrent
// MarkChunkStored cannot trick it into releasing the wrong bucket.
func (s *Store) release(ctx context.Context, q q, snapID, userID string) error {
	now := ns(s.now())
	rows, err := q.QueryContext(ctx,
		`SELECT hash FROM snapshot_chunks WHERE snapshot_id=?`, snapID)
	if err != nil {
		return err
	}
	var hashes [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			_ = rows.Close()
			return err
		}
		hashes = append(hashes, h)
	}
	_ = rows.Close()
	var dUsed, dRes int64
	for _, h := range hashes {
		var rc int64
		var st string
		var size int64
		err := q.QueryRowContext(ctx,
			`UPDATE chunks SET refcount=refcount-1 WHERE user_id=? AND hash=? RETURNING refcount,state,size`,
			userID, h).Scan(&rc, &st, &size)
		if err != nil {
			return err
		}
		switch {
		case rc == 0 && st == meta.ChunkStored:
			if _, err := q.ExecContext(ctx,
				`UPDATE chunks SET zero_ref_since=? WHERE user_id=? AND hash=? AND refcount=0`, now, userID, h); err != nil {
				return err
			}
			dUsed += size
		case rc == 0 && st == meta.ChunkReserved:
			if _, err := q.ExecContext(ctx,
				`DELETE FROM chunks WHERE user_id=? AND hash=?`, userID, h); err != nil {
				return err
			}
			dRes += size
		}
	}
	var mh []byte
	var msz int64
	err = q.QueryRowContext(ctx,
		`SELECT manifest_hash, manifest_size FROM snapshots WHERE id=?`, snapID).Scan(&mh, &msz)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // snapshot already released
	}
	if err != nil {
		return err
	}
	var mrc int64
	err = q.QueryRowContext(ctx,
		`UPDATE manifests SET refcount=refcount-1 WHERE user_id=? AND hash=? RETURNING refcount`,
		userID, mh).Scan(&mrc)
	if err == nil && mrc == 0 {
		if _, err := q.ExecContext(ctx,
			`UPDATE manifests SET zero_ref_since=? WHERE user_id=? AND hash=?`, now, userID, mh); err != nil {
			return err
		}
		dUsed += msz
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM snapshot_chunks WHERE snapshot_id=?`, snapID); err != nil {
		return err
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM snapshots WHERE id=?`, snapID); err != nil {
		return err
	}
	if _, err := q.ExecContext(ctx,
		`UPDATE usage SET used_bytes=used_bytes-?, reserved_bytes=reserved_bytes-? WHERE user_id=?`,
		dUsed, dRes, userID); err != nil {
		return err
	}
	return nil
}

const snapCols = `id, user_id, app, slot, parent_id, device, label, state, manifest_hash, manifest_size, total_bytes, file_count, created_at, committed_at, expires_at`

func (s *Store) CommitSnapshot(ctx context.Context, userID, snapshotID string, o meta.CommitOptions) (meta.CommitResult, error) {
	var res meta.CommitResult
	err := s.wtx(ctx, func(q q) error {
		_, _, err := lockUsage(ctx, q, userID)
		if err != nil {
			return err
		}
		sn, err := s.getSnap(ctx, q, snapshotID)
		if err != nil {
			return err
		}
		if sn.State != meta.StatePending {
			return meta.ErrExists
		}
		var missing int64
		if err := q.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM snapshot_chunks sc JOIN chunks c ON c.user_id=sc.user_id AND c.hash=sc.hash
			 WHERE sc.snapshot_id=? AND c.state != ?`, snapshotID, meta.ChunkStored).Scan(&missing); err != nil {
			return err
		}
		if missing > 0 {
			return &meta.IncompleteError{Missing: int(missing)}
		}
		var head string
		err = q.QueryRowContext(ctx,
			`SELECT COALESCE(head_snapshot_id,'') FROM slots WHERE user_id=? AND app=? AND name=?`,
			userID, sn.App, sn.Slot).Scan(&head)
		if errors.Is(err, sql.ErrNoRows) {
			return meta.ErrNotFound
		}
		if err != nil {
			return err
		}
		if !o.Force && head != o.ExpectedHead {
			headSnap, herr := s.getSnap(ctx, q, head)
			if herr != nil && head != "" {
				return herr
			}
			return &meta.ConflictError{Head: headSnap}
		}
		now := ns(s.now())
		if _, err := q.ExecContext(ctx,
			`UPDATE snapshots SET state=?, committed_at=?, parent_id=? WHERE id=?`,
			meta.StateCommitted, now, head, snapshotID); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx,
			`UPDATE slots SET head_snapshot_id=?, updated_at=? WHERE user_id=? AND app=? AND name=?`,
			snapshotID, now, userID, sn.App, sn.Slot); err != nil {
			return err
		}
		sn.State = meta.StateCommitted
		sn.ParentID = head
		ct := time.Unix(0, now).UTC()
		sn.CommittedAt = &ct
		res.Snapshot = sn
		// Retention: prune committed snapshots beyond keep_last or older
		// than max_age, never the new head.
		rows, err := q.QueryContext(ctx,
			`SELECT id, created_at FROM snapshots WHERE user_id=? AND app=? AND slot=? AND state=?
			 ORDER BY created_at DESC, id DESC`, userID, sn.App, sn.Slot, meta.StateCommitted)
		if err != nil {
			return err
		}
		var pruneIDs []string
		idx := 0
		cutoff := int64(0)
		if o.MaxAge > 0 {
			cutoff = now - int64(o.MaxAge)
		}
		for rows.Next() {
			var sid string
			var created int64
			if err := rows.Scan(&sid, &created); err != nil {
				_ = rows.Close()
				return err
			}
			if sid == snapshotID {
				continue
			}
			idx++
			if (o.KeepLast > 0 && idx >= o.KeepLast) || (cutoff > 0 && created < cutoff) {
				pruneIDs = append(pruneIDs, sid)
			}
		}
		_ = rows.Close()
		for _, pid := range pruneIDs {
			if err := s.release(ctx, q, pid, userID); err != nil {
				return err
			}
			res.Pruned = append(res.Pruned, pid)
		}
		return nil
	})
	return res, err
}

func (s *Store) getSnap(ctx context.Context, q q, id string) (meta.Snapshot, error) {
	var sn meta.Snapshot
	var com, exp sql.NullInt64
	var created int64
	var mh []byte
	err := q.QueryRowContext(ctx, `SELECT `+snapCols+` FROM snapshots WHERE id=?`, id).
		Scan(&sn.ID, &sn.UserID, &sn.App, &sn.Slot, &sn.ParentID, &sn.Device, &sn.Label, &sn.State,
			&mh, &sn.ManifestSize, &sn.TotalBytes, &sn.FileCount, &created, &com, &exp)
	copy(sn.ManifestHash[:], mh)
	if errors.Is(err, sql.ErrNoRows) {
		return sn, meta.ErrNotFound
	}
	if err != nil {
		return sn, err
	}
	sn.CreatedAt = time.Unix(0, created).UTC()
	sn.CommittedAt = tm(com)
	sn.ExpiresAt = tm(exp)
	return sn, nil
}

func (s *Store) AbortSnapshot(ctx context.Context, userID, snapshotID string) error {
	return s.wtx(ctx, func(q q) error {
		sn, err := s.getSnap(ctx, q, snapshotID)
		if err != nil {
			return err
		}
		if sn.State != meta.StatePending {
			return meta.ErrNotExpected
		}
		return s.release(ctx, q, snapshotID, userID)
	})
}

func (s *Store) ExpirePending(ctx context.Context, now time.Time, limit int) (int, error) {
	var ids []string
	err := s.wtx(ctx, func(q q) error {
		rows, err := q.QueryContext(ctx,
			`SELECT id, user_id FROM snapshots WHERE state=? AND expires_at IS NOT NULL AND expires_at < ? LIMIT ?`,
			meta.StatePending, ns(now), limit)
		if err != nil {
			return err
		}
		type pending struct{ id, uid string }
		var ps []pending
		for rows.Next() {
			var p pending
			if err := rows.Scan(&p.id, &p.uid); err != nil {
				_ = rows.Close()
				return err
			}
			ps = append(ps, p)
		}
		_ = rows.Close()
		for _, p := range ps {
			if err := s.release(ctx, q, p.id, p.uid); err != nil {
				return err
			}
		}
		ids = make([]string, len(ps))
		for i, p := range ps {
			ids[i] = p.id
		}
		return nil
	})
	return len(ids), err
}

func (s *Store) GetSnapshot(ctx context.Context, userID, app, slot, id string) (meta.Snapshot, error) {
	sn, err := s.getSnap(ctx, s.r, id)
	if err != nil {
		return sn, err
	}
	if sn.UserID != userID || sn.App != app || sn.Slot != slot {
		return sn, meta.ErrNotFound
	}
	return sn, nil
}

func (s *Store) ListSnapshots(ctx context.Context, userID, app, slot, cursor string, limit int) ([]meta.Snapshot, string, error) {
	cNS, cID, err := meta.DecodeCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	query := `SELECT ` + snapCols + ` FROM snapshots WHERE user_id=? AND app=? AND slot=?`
	args := []any{userID, app, slot}
	if cursor != "" {
		query += ` AND (created_at < ? OR (created_at = ? AND id < ?))`
		args = append(args, cNS, cNS, cID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []meta.Snapshot
	for rows.Next() {
		var sn meta.Snapshot
		var com, exp sql.NullInt64
		var created int64
		var mh []byte
		if err := rows.Scan(&sn.ID, &sn.UserID, &sn.App, &sn.Slot, &sn.ParentID, &sn.Device, &sn.Label, &sn.State,
			&mh, &sn.ManifestSize, &sn.TotalBytes, &sn.FileCount, &created, &com, &exp); err != nil {
			return nil, "", err
		}
		copy(sn.ManifestHash[:], mh)
		sn.CreatedAt = time.Unix(0, created).UTC()
		sn.CommittedAt = tm(com)
		sn.ExpiresAt = tm(exp)
		out = append(out, sn)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	var next string
	if len(out) > limit {
		out = out[:limit]
		last := ns(out[len(out)-1].CreatedAt)
		next = meta.EncodeCursor(last, out[len(out)-1].ID)
	}
	return out, next, nil
}

func (s *Store) DeleteSnapshot(ctx context.Context, userID, app, slot, id string) error {
	return s.wtx(ctx, func(q q) error {
		sn, err := s.getSnap(ctx, q, id)
		if err != nil {
			return err
		}
		if sn.UserID != userID || sn.App != app || sn.Slot != slot {
			return meta.ErrNotFound
		}
		if sn.State == meta.StateCommitted {
			var head string
			if err := q.QueryRowContext(ctx,
				`SELECT COALESCE(head_snapshot_id,'') FROM slots WHERE user_id=? AND app=? AND name=?`,
				userID, app, slot).Scan(&head); err != nil {
				return err
			}
			if head == id {
				return meta.ErrExists
			}
		}
		return s.release(ctx, q, id, userID)
	})
}

func (s *Store) ListApps(ctx context.Context, userID string) ([]meta.AppSummary, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT s.app, (SELECT COUNT(*) FROM slots sl WHERE sl.user_id=s.user_id AND sl.app=s.app), COUNT(*)
		 FROM snapshots s WHERE s.user_id=? GROUP BY s.app ORDER BY s.app`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.AppSummary
	for rows.Next() {
		var a meta.AppSummary
		if err := rows.Scan(&a.App, &a.Slots, &a.Snapshots); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ListSlots(ctx context.Context, userID, app string) ([]meta.Slot, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT user_id, app, name, COALESCE(head_snapshot_id,''), created_at, updated_at
		 FROM slots WHERE user_id=? AND app=? ORDER BY name`, userID, app)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSlots(rows)
}

func scanSlots(rows *sql.Rows) ([]meta.Slot, error) {
	var out []meta.Slot
	for rows.Next() {
		var sl meta.Slot
		var created, updated int64
		if err := rows.Scan(&sl.UserID, &sl.App, &sl.Name, &sl.HeadSnapshotID, &created, &updated); err != nil {
			return nil, err
		}
		sl.CreatedAt = time.Unix(0, created).UTC()
		sl.UpdatedAt = time.Unix(0, updated).UTC()
		out = append(out, sl)
	}
	return out, rows.Err()
}

func (s *Store) GetSlot(ctx context.Context, userID, app, slot string) (meta.Slot, error) {
	var sl meta.Slot
	var created, updated int64
	err := s.r.QueryRowContext(ctx,
		`SELECT user_id, app, name, COALESCE(head_snapshot_id,''), created_at, updated_at
		 FROM slots WHERE user_id=? AND app=? AND name=?`, userID, app, slot).
		Scan(&sl.UserID, &sl.App, &sl.Name, &sl.HeadSnapshotID, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return sl, meta.ErrNotFound
	}
	if err != nil {
		return sl, err
	}
	sl.CreatedAt = time.Unix(0, created).UTC()
	sl.UpdatedAt = time.Unix(0, updated).UTC()
	return sl, nil
}

func (s *Store) DeleteSlot(ctx context.Context, userID, app, slot string) error {
	return s.wtx(ctx, func(q q) error {
		rows, err := q.QueryContext(ctx,
			`SELECT id FROM snapshots WHERE user_id=? AND app=? AND slot=?`, userID, app, slot)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		_ = rows.Close()
		for _, id := range ids {
			if err := s.release(ctx, q, id, userID); err != nil {
				return err
			}
		}
		res, err := q.ExecContext(ctx,
			`DELETE FROM slots WHERE user_id=? AND app=? AND name=?`, userID, app, slot)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
}

func (s *Store) Usage(ctx context.Context, userID string) (meta.Usage, error) {
	var u meta.Usage
	err := s.r.QueryRowContext(ctx,
		`SELECT used_bytes, reserved_bytes FROM usage WHERE user_id=?`, userID).Scan(&u.UsedBytes, &u.ReservedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		u.UsedBytes, u.ReservedBytes = 0, 0
	} else if err != nil {
		return u, err
	}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM slots WHERE user_id=?`, userID).Scan(&u.Slots); err != nil {
		return u, err
	}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM snapshots WHERE user_id=?`, userID).Scan(&u.Snapshots); err != nil {
		return u, err
	}
	var quota sql.NullInt64
	if err := s.r.QueryRowContext(ctx, `SELECT quota_bytes FROM users WHERE id=?`, userID).Scan(&quota); err == nil && quota.Valid {
		u.QuotaBytes = quota.Int64
	}
	return u, nil
}

func (s *Store) UnreferencedChunks(ctx context.Context, olderThan time.Time, limit int) ([]meta.ChunkRow, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT user_id, hash, size, state, zero_ref_since FROM chunks
		 WHERE refcount=0 AND zero_ref_since IS NOT NULL AND zero_ref_since < ? ORDER BY zero_ref_since LIMIT ?`,
		ns(olderThan), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.ChunkRow
	for rows.Next() {
		var c meta.ChunkRow
		var zrs sql.NullInt64
		var hb []byte
		if err := rows.Scan(&c.UserID, &hb, &c.Size, &c.State, &zrs); err != nil {
			return nil, err
		}
		copy(c.Hash[:], hb)
		c.ZeroRefSince = tm(zrs)
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkDeleting flips a zero-ref chunk to deleting for the GC protocol.
func (s *Store) MarkDeleting(ctx context.Context, userID string, h api.Hash) (bool, error) {
	var ok bool
	err := s.wtx(ctx, func(q q) error {
		res, err := q.ExecContext(ctx,
			`UPDATE chunks SET state=? WHERE user_id=? AND hash=? AND refcount=0`,
			meta.ChunkDeleting, userID, h[:])
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		ok = n > 0
		return nil
	})
	return ok, err
}

func (s *Store) DeleteChunkRow(ctx context.Context, userID string, h api.Hash) (bool, error) {
	var ok bool
	err := s.wtx(ctx, func(q q) error {
		res, err := q.ExecContext(ctx,
			`DELETE FROM chunks WHERE user_id=? AND hash=? AND refcount=0`, userID, h[:])
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		ok = n > 0
		return nil
	})
	return ok, err
}

func (s *Store) UnreferencedManifests(ctx context.Context, olderThan time.Time, limit int) ([]meta.ManifestRow, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT user_id, hash, size, zero_ref_since FROM manifests
		 WHERE refcount=0 AND zero_ref_since IS NOT NULL AND zero_ref_since < ? ORDER BY zero_ref_since LIMIT ?`,
		ns(olderThan), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.ManifestRow
	for rows.Next() {
		var m meta.ManifestRow
		var zrs sql.NullInt64
		var hb []byte
		if err := rows.Scan(&m.UserID, &hb, &m.Size, &zrs); err != nil {
			return nil, err
		}
		copy(m.Hash[:], hb)
		m.ZeroRefSince = tm(zrs)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteManifestRow(ctx context.Context, userID string, h api.Hash) (bool, error) {
	var ok bool
	err := s.wtx(ctx, func(q q) error {
		res, err := q.ExecContext(ctx,
			`DELETE FROM manifests WHERE user_id=? AND hash=? AND refcount=0`, userID, h[:])
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		ok = n > 0
		return nil
	})
	return ok, err
}

func (s *Store) PurgedUsers(ctx context.Context, limit int) ([]meta.User, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT `+userCols+` FROM users WHERE deleted_at IS NOT NULL ORDER BY deleted_at LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.User
	for rows.Next() {
		var u meta.User
		var quota, deleted, created sql.NullInt64
		var disabled int
		if err := rows.Scan(&u.ID, &u.Subject, &u.Tier, &quota, &disabled, &deleted, &created); err != nil {
			return nil, err
		}
		if quota.Valid {
			u.QuotaBytes = &quota.Int64
		}
		u.Disabled = disabled != 0
		u.DeletedAt = tm(deleted)
		u.CreatedAt = time.Unix(0, created.Int64).UTC()
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) FinishPurge(ctx context.Context, userID string) error {
	return s.wtx(ctx, func(q q) error {
		rows, err := q.QueryContext(ctx, `SELECT id FROM snapshots WHERE user_id=?`, userID)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		_ = rows.Close()
		for _, id := range ids {
			if err := s.release(ctx, q, id, userID); err != nil {
				return err
			}
		}
		for _, stmt := range []string{
			`DELETE FROM tokens WHERE user_id=?`,
			`DELETE FROM usage WHERE user_id=?`,
			`DELETE FROM slots WHERE user_id=?`,
			`DELETE FROM chunks WHERE user_id=?`,
			`DELETE FROM manifests WHERE user_id=?`,
			`DELETE FROM users WHERE id=?`,
		} {
			if _, err := q.ExecContext(ctx, stmt, userID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	var ok bool
	err := s.wtx(ctx, func(q q) error {
		exp := ns(s.now().Add(ttl))
		res, err := q.ExecContext(ctx,
			`INSERT INTO leases(name,holder,expires_at) VALUES(?,?,?)
			 ON CONFLICT(name) DO UPDATE SET holder=excluded.holder, expires_at=excluded.expires_at
			 WHERE leases.expires_at < ? OR leases.holder = ?`,
			name, holder, exp, ns(s.now()), holder)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		ok = n > 0
		return nil
	})
	return ok, err
}

func (s *Store) Fsck(ctx context.Context, repair bool) (meta.FsckReport, error) {
	var rep meta.FsckReport
	err := s.wtx(ctx, func(q q) error {
		// Orphan snapshot_chunks without a snapshot.
		rows, err := q.QueryContext(ctx,
			`SELECT sc.snapshot_id FROM snapshot_chunks sc
			 LEFT JOIN snapshots s ON s.id=sc.snapshot_id WHERE s.id IS NULL`)
		if err != nil {
			return err
		}
		var orphans []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			orphans = append(orphans, id)
			rep.OrphanRefs++
			rep.Issues = append(rep.Issues, "orphan snapshot_chunks for "+id)
		}
		_ = rows.Close()
		if repair {
			for _, id := range orphans {
				if _, err := q.ExecContext(ctx, `DELETE FROM snapshot_chunks WHERE snapshot_id=?`, id); err != nil {
					return err
				}
			}
		}
		// Recompute chunk refcounts.
		type ck struct {
			uid    string
			h      []byte
			rc     int64
			expect int64
			size   int64
			state  string
			zrs    sql.NullInt64
		}
		rows, err = q.QueryContext(ctx,
			`SELECT c.user_id, c.hash, c.refcount, c.size, c.state, c.zero_ref_since,
				(SELECT COUNT(*) FROM snapshot_chunks sc JOIN snapshots s ON s.id=sc.snapshot_id
				 WHERE sc.user_id=c.user_id AND sc.hash=c.hash) AS expect
			 FROM chunks c`)
		if err != nil {
			return err
		}
		var cks []ck
		for rows.Next() {
			var c ck
			if err := rows.Scan(&c.uid, &c.h, &c.rc, &c.size, &c.state, &c.zrs, &c.expect); err != nil {
				_ = rows.Close()
				return err
			}
			cks = append(cks, c)
		}
		_ = rows.Close()
		used := map[string]int64{}
		resvd := map[string]int64{}
		for _, c := range cks {
			if c.rc != c.expect {
				rep.Issues = append(rep.Issues, fmt.Sprintf("chunk %s refcount %d expected %d", c.uid, c.rc, c.expect))
				rep.Refcounts++
				if repair {
					// state sanity is also repaired below.
					var zrs any
					if c.expect == 0 && !c.zrs.Valid {
						zrs = ns(s.now())
					}
					if c.expect > 0 {
						zrs = nil
					}
					var newState string
					if c.expect > 0 && c.state == meta.ChunkDeleting {
						newState = meta.ChunkReserved
					}
					if newState != "" {
						if _, err := q.ExecContext(ctx,
							`UPDATE chunks SET refcount=?, state=?, zero_ref_since=? WHERE user_id=? AND hash=?`,
							c.expect, newState, zrs, c.uid, c.h); err != nil {
							return err
						}
					} else {
						if _, err := q.ExecContext(ctx,
							`UPDATE chunks SET refcount=?, zero_ref_since=? WHERE user_id=? AND hash=?`,
							c.expect, zrs, c.uid, c.h); err != nil {
							return err
						}
					}
					c.rc = c.expect
					c.zrs.Valid = zrs != nil
				}
			}
			if c.state == meta.ChunkStored && c.rc > 0 {
				used[c.uid] += c.size
			}
			if c.state == meta.ChunkReserved {
				resvd[c.uid] += c.size
			}
		}
		// Reserved rows with no references should not exist.
		rows, err = q.QueryContext(ctx,
			`SELECT user_id, hash, size FROM chunks WHERE state=? AND refcount=0`, meta.ChunkReserved)
		if err != nil {
			return err
		}
		type rk struct {
			uid string
			h   []byte
			sz  int64
		}
		var rks []rk
		for rows.Next() {
			var r rk
			if err := rows.Scan(&r.uid, &r.h, &r.sz); err != nil {
				_ = rows.Close()
				return err
			}
			rks = append(rks, r)
			rep.Issues = append(rep.Issues, "reserved chunk with refcount 0")
		}
		_ = rows.Close()
		if repair {
			for _, r := range rks {
				if _, err := q.ExecContext(ctx, `DELETE FROM chunks WHERE user_id=? AND hash=?`, r.uid, r.h); err != nil {
					return err
				}
				resvd[r.uid] -= r.sz
			}
		}
		// Manifest refcounts.
		rows, err = q.QueryContext(ctx,
			`SELECT m.user_id, m.hash, m.refcount, m.size,
				(SELECT COUNT(*) FROM snapshots s WHERE s.user_id=m.user_id AND s.manifest_hash=m.hash) AS expect
			 FROM manifests m`)
		if err != nil {
			return err
		}
		type mk struct {
			uid    string
			h      []byte
			rc     int64
			expect int64
			size   int64
		}
		var mks []mk
		for rows.Next() {
			var m mk
			if err := rows.Scan(&m.uid, &m.h, &m.rc, &m.size, &m.expect); err != nil {
				_ = rows.Close()
				return err
			}
			mks = append(mks, m)
		}
		_ = rows.Close()
		for _, m := range mks {
			if m.rc != m.expect {
				rep.Issues = append(rep.Issues, fmt.Sprintf("manifest refcount %d expected %d", m.rc, m.expect))
				rep.Refcounts++
				if repair {
					if _, err := q.ExecContext(ctx,
						`UPDATE manifests SET refcount=?, zero_ref_since=CASE WHEN ?=0 THEN ? ELSE NULL END WHERE user_id=? AND hash=?`,
						m.expect, m.expect, ns(s.now()), m.uid, m.h); err != nil {
						return err
					}
					m.rc = m.expect
				}
			}
			if m.rc > 0 {
				used[m.uid] += m.size
			}
		}
		// Usage table.
		rows, err = q.QueryContext(ctx, `SELECT user_id, used_bytes, reserved_bytes FROM usage`)
		if err != nil {
			return err
		}
		type ur struct {
			uid      string
			used, rv int64
		}
		var urs []ur
		for rows.Next() {
			var u ur
			if err := rows.Scan(&u.uid, &u.used, &u.rv); err != nil {
				_ = rows.Close()
				return err
			}
			urs = append(urs, u)
		}
		_ = rows.Close()
		for _, u := range urs {
			eu, er := used[u.uid], resvd[u.uid]
			if u.used != eu || u.rv != er {
				rep.Issues = append(rep.Issues, fmt.Sprintf("usage %s used=%d/%d reserved=%d/%d", u.uid, u.used, eu, u.rv, er))
				rep.UsageFixed++
				if repair {
					if _, err := q.ExecContext(ctx,
						`UPDATE usage SET used_bytes=?, reserved_bytes=? WHERE user_id=?`, eu, er, u.uid); err != nil {
						return err
					}
				}
			}
		}
		rep.Repaired = repair && len(rep.Issues) > 0
		return nil
	})
	return rep, err
}
