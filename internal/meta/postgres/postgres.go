// SPDX-License-Identifier: 0BSD

// Package postgres implements meta.Store on PostgreSQL via pgx/v5.
// Write paths lock the usage row with SELECT FOR UPDATE to serialize
// quota decisions per user and retry on serialization or deadlock
// errors. All dials go through internal/netx so MPTCP stays disabled.
package postgres

import (
	"context"
	crand "crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

//go:embed migrations/*.sql
var migFS embed.FS

func init() {
	meta.RegisterDriver("postgres", func(ctx context.Context, dsn string, opt meta.Options) (meta.Store, error) {
		return Open(ctx, dsn, 0, 0, opt)
	})
}

// Store is the postgres backend.
type Store struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

var _ meta.Store = (*Store)(nil)

// Open builds a pool from dsn with netx dialing.
func Open(ctx context.Context, dsn string, maxConns, minConns int32, opt meta.Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("meta postgres: %w", err)
	}
	dialer := netx.Dialer()
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	if minConns > 0 {
		cfg.MinConns = minConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("meta postgres: %w", err)
	}
	s := &Store{pool: pool, clock: opt.Clock}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s, nil
}

func (s *Store) now() time.Time { return s.clock() }

func newUserID() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func ns(t time.Time) int64 { return t.UnixNano() }

func nsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixNano()
}

func tm(v *int64) *time.Time {
	if v == nil {
		return nil
	}
	t := time.Unix(0, *v).UTC()
	return &t
}

// qtx abstracts pgx.Conn and pgx.Tx.
type qtx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func retryable(err error) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code == "40001" || pe.Code == "40P01" || pe.Code == "23505"
	}
	return false
}

const maxAttempts = 5

// wtx runs fn in a transaction, retrying on serialization failures.
func (s *Store) wtx(ctx context.Context, fn func(q qtx) error) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = s.tryTx(ctx, fn)
		if !retryable(err) && !errors.Is(err, meta.ErrContended) {
			return err
		}
	}
	return err
}

func (s *Store) tryTx(ctx context.Context, fn func(q qtx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const advisoryKey = 727272

// Migrate applies embedded migrations under an advisory lock.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryKey); err != nil {
		return err
	}
	defer conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, advisoryKey)
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
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at BIGINT NOT NULL)`); err != nil {
		return err
	}
	var have int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&have); err != nil {
		return err
	}
	for i, f := range files {
		ver := i + 1
		if ver <= have {
			continue
		}
		data, err := migFS.ReadFile(f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("meta postgres: migration %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES($1,$2)`, ver, ns(s.now())); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

const userCols = `id, subject, tier, quota_bytes, disabled, deleted_at, created_at`

func scanUserInto(u *meta.User, quota *int64, deleted, created *int64, disabled *bool) {
	u.QuotaBytes = quota
	u.DeletedAt = tm(deleted)
	u.Disabled = disabled != nil && *disabled
	if created != nil {
		u.CreatedAt = time.Unix(0, *created).UTC()
	}
}

func (s *Store) getUser(ctx context.Context, q qtx, where string, arg any) (meta.User, error) {
	var u meta.User
	var quota, deleted, created *int64
	var disabled bool
	err := q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE `+where+`=$1`, arg).
		Scan(&u.ID, &u.Subject, &u.Tier, &quota, &disabled, &deleted, &created)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, meta.ErrNotFound
	}
	if err != nil {
		return u, err
	}
	scanUserInto(&u, quota, deleted, created, &disabled)
	return u, nil
}

func (s *Store) UpsertUser(ctx context.Context, subject, tier string) (meta.User, bool, error) {
	var u meta.User
	var created bool
	err := s.wtx(ctx, func(q qtx) error {
		id, err := newUserID()
		if err != nil {
			return err
		}
		tag, err := q.Exec(ctx, `INSERT INTO users(id,subject,tier,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(subject) DO NOTHING`,
			id, subject, tier, ns(s.now()))
		if err != nil {
			return err
		}
		created = tag.RowsAffected() > 0
		u, err = s.getUser(ctx, q, "subject", subject)
		return err
	})
	return u, created, err
}

func (s *Store) GetUser(ctx context.Context, id string) (meta.User, error) {
	return s.getUser(ctx, s.pool, "id", id)
}

func (s *Store) GetUserBySubject(ctx context.Context, subject string) (meta.User, error) {
	return s.getUser(ctx, s.pool, "subject", subject)
}

func (s *Store) ListUsers(ctx context.Context, after string, limit int) ([]meta.User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.User
	for rows.Next() {
		var u meta.User
		var quota, deleted, created *int64
		var disabled bool
		if err := rows.Scan(&u.ID, &u.Subject, &u.Tier, &quota, &disabled, &deleted, &created); err != nil {
			return nil, err
		}
		scanUserInto(&u, quota, deleted, created, &disabled)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUser(ctx context.Context, id string, p meta.UserPatch) (meta.User, error) {
	var u meta.User
	err := s.wtx(ctx, func(q qtx) error {
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
		tag, err := q.Exec(ctx, `UPDATE users SET tier=$1, quota_bytes=$2, disabled=$3 WHERE id=$4`,
			u.Tier, u.QuotaBytes, u.Disabled, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
	return u, err
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx, `UPDATE users SET disabled=TRUE, deleted_at=$1 WHERE id=$2 AND deleted_at IS NULL`, ns(s.now()), id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
}

// #nosec G101 -- column stores a hash, not a credential
const tokenCols = `id, user_id, secret_hash, name, scopes, apps, created_at, expires_at, revoked_at, last_used_at`

func scanTokenRows(rows pgx.Rows) ([]meta.Token, error) {
	var out []meta.Token
	for rows.Next() {
		var t meta.Token
		var exp, rev, last *int64
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

func (s *Store) CreateToken(ctx context.Context, t meta.Token) error {
	created := t.CreatedAt
	if created.IsZero() {
		created = s.now()
	}
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `INSERT INTO tokens(`+tokenCols+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			t.ID, t.UserID, t.SecretHash[:], t.Name, strings.Join(t.Scopes, ","), strings.Join(t.Apps, ","),
			ns(created), nsPtr(t.ExpiresAt), nsPtr(t.RevokedAt), nsPtr(t.LastUsedAt))
		return err
	})
}

func (s *Store) GetToken(ctx context.Context, id string) (meta.Token, error) {
	var t meta.Token
	var exp, rev, last *int64
	var scopes, apps string
	var created int64
	var sh []byte
	err := s.pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM tokens WHERE id=$1`, id).
		Scan(&t.ID, &t.UserID, &sh, &t.Name, &scopes, &apps, &created, &exp, &rev, &last)
	copy(t.SecretHash[:], sh)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, meta.ErrNotFound
	}
	if err != nil {
		return t, err
	}
	t.CreatedAt = time.Unix(0, created).UTC()
	t.Scopes = splitCSV(scopes)
	t.Apps = splitCSV(apps)
	t.ExpiresAt = tm(exp)
	t.RevokedAt = tm(rev)
	t.LastUsedAt = tm(last)
	return t, nil
}

func (s *Store) TouchToken(ctx context.Context, id string, at time.Time) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `UPDATE tokens SET last_used_at=$1 WHERE id=$2`, ns(at), id)
		return err
	})
}

func (s *Store) ListTokens(ctx context.Context, userID string) ([]meta.Token, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+tokenCols+` FROM tokens WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTokenRows(rows)
}

func (s *Store) RevokeToken(ctx context.Context, id string) error {
	return s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx, `UPDATE tokens SET revoked_at=$1 WHERE id=$2 AND revoked_at IS NULL`, ns(s.now()), id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
}

// lockUsage ensures the usage row exists and locks it FOR UPDATE,
// serializing quota decisions per user.
func lockUsage(ctx context.Context, q qtx, userID string) (used, reserved int64, err error) {
	if _, err = q.Exec(ctx, `INSERT INTO usage(user_id) VALUES($1) ON CONFLICT DO NOTHING`, userID); err != nil {
		return 0, 0, err
	}
	err = q.QueryRow(ctx, `SELECT used_bytes, reserved_bytes FROM usage WHERE user_id=$1 FOR UPDATE`, userID).
		Scan(&used, &reserved)
	return used, reserved, err
}

func (s *Store) BeginSnapshot(ctx context.Context, p meta.BeginParams) (meta.BeginResult, error) {
	var res meta.BeginResult
	err := s.wtx(ctx, func(q qtx) error {
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
		if err := q.QueryRow(ctx,
			`SELECT COUNT(*) FROM snapshots WHERE user_id=$1 AND state=$2`, p.UserID, meta.StatePending).Scan(&pending); err != nil {
			return err
		}
		if p.Limits.MaxPendingSnapshots > 0 && pending >= p.Limits.MaxPendingSnapshots {
			return meta.ErrPendingLimit
		}
		var slotExists bool
		var one int
		err = q.QueryRow(ctx,
			`SELECT 1 FROM slots WHERE user_id=$1 AND app=$2 AND name=$3`, p.UserID, p.App, p.Slot).Scan(&one)
		switch {
		case err == nil:
			slotExists = true
		case errors.Is(err, pgx.ErrNoRows):
			var slots int
			if err := q.QueryRow(ctx, `SELECT COUNT(*) FROM slots WHERE user_id=$1`, p.UserID).Scan(&slots); err != nil {
				return err
			}
			if p.Limits.MaxSlots > 0 && slots >= p.Limits.MaxSlots {
				return meta.ErrSlotLimit
			}
		default:
			return err
		}
		type cplan struct {
			h       api.Hash
			size    int64
			set     string
			insert  bool
			missing bool
		}
		seen := map[api.Hash]int64{}
		var uniq []api.ChunkRef
		for _, c := range p.Chunks {
			if prev, ok := seen[c.Hash]; ok {
				if prev != int64(c.Size) {
					return fmt.Errorf("meta: conflicting sizes for chunk %s", c.Hash)
				}
				continue
			}
			seen[c.Hash] = int64(c.Size)
			uniq = append(uniq, c)
		}
		var deltaReserved, deltaUsed int64
		var plans []cplan
		for _, r := range uniq {
			var st string
			var rc, sz int64
			err := q.QueryRow(ctx,
				`SELECT state, refcount, size FROM chunks WHERE user_id=$1 AND hash=$2`, p.UserID, r.Hash[:]).Scan(&st, &rc, &sz)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				plans = append(plans, cplan{h: r.Hash, size: int64(r.Size), insert: true, missing: true})
				deltaReserved += int64(r.Size)
			case err != nil:
				return err
			case st == meta.ChunkStored:
				plans = append(plans, cplan{h: r.Hash, size: sz})
				if rc == 0 {
					deltaUsed += sz
				}
			case st == meta.ChunkReserved:
				plans = append(plans, cplan{h: r.Hash, size: sz, missing: true})
			case st == meta.ChunkDeleting:
				plans = append(plans, cplan{h: r.Hash, size: sz, set: meta.ChunkReserved, missing: true})
				deltaReserved += sz
			}
		}
		var mrc, msz int64
		err = q.QueryRow(ctx,
			`SELECT refcount, size FROM manifests WHERE user_id=$1 AND hash=$2`, p.UserID, p.ManifestHash[:]).Scan(&mrc, &msz)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
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
		if _, err := q.Exec(ctx, `INSERT INTO snapshots(id,user_id,app,slot,parent_id,device,label,state,manifest_hash,manifest_size,total_bytes,file_count,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			id, p.UserID, p.App, p.Slot, p.ParentID, p.Device, p.Label, meta.StatePending,
			p.ManifestHash[:], p.ManifestSize, p.TotalBytes, p.FileCount, ns(s.now()), exp); err != nil {
			return err
		}
		if !slotExists {
			if _, err := q.Exec(ctx,
				`INSERT INTO slots(user_id,app,name,created_at,updated_at) VALUES($1,$2,$3,$4,$5)`,
				p.UserID, p.App, p.Slot, ns(s.now()), ns(s.now())); err != nil {
				return err
			}
		}
		for _, pl := range plans {
			if _, err := q.Exec(ctx,
				`INSERT INTO snapshot_chunks(snapshot_id,user_id,hash) VALUES($1,$2,$3)`, id, p.UserID, pl.h[:]); err != nil {
				return err
			}
			switch {
			case pl.insert:
				if _, err := q.Exec(ctx,
					`INSERT INTO chunks(user_id,hash,size,state,refcount,created_at) VALUES($1,$2,$3,$4,1,$5)`,
					p.UserID, pl.h[:], pl.size, meta.ChunkReserved, ns(s.now())); err != nil {
					return err
				}
			case pl.set != "":
				tag, err := q.Exec(ctx,
					`UPDATE chunks SET state=$1, refcount=refcount+1, zero_ref_since=NULL WHERE user_id=$2 AND hash=$3`,
					pl.set, p.UserID, pl.h[:])
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					return meta.ErrContended
				}
			default:
				tag, err := q.Exec(ctx,
					`UPDATE chunks SET refcount=refcount+1, zero_ref_since=NULL WHERE user_id=$1 AND hash=$2`,
					p.UserID, pl.h[:])
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					return meta.ErrContended
				}
			}
			if pl.missing {
				res.Missing = append(res.Missing, pl.h)
			}
		}
		if _, err := q.Exec(ctx,
			`INSERT INTO manifests(user_id,hash,size,refcount) VALUES($1,$2,$3,1)
			 ON CONFLICT(user_id,hash) DO UPDATE SET refcount=manifests.refcount+1, zero_ref_since=NULL`,
			p.UserID, p.ManifestHash[:], p.ManifestSize); err != nil {
			return err
		}
		if _, err := q.Exec(ctx,
			`UPDATE usage SET used_bytes=used_bytes+$1, reserved_bytes=reserved_bytes+$2 WHERE user_id=$3`,
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
	return s.wtx(ctx, func(q qtx) error {
		var st string
		err := q.QueryRow(ctx,
			`SELECT state FROM snapshots WHERE id=$1 AND user_id=$2`, snapshotID, userID).Scan(&st)
		if errors.Is(err, pgx.ErrNoRows) {
			return meta.ErrNotFound
		}
		if err != nil {
			return err
		}
		if st != meta.StatePending {
			return meta.ErrNotExpected
		}
		var hasRef bool
		err = q.QueryRow(ctx,
			`SELECT TRUE FROM snapshot_chunks WHERE snapshot_id=$1 AND hash=$2`, snapshotID, h[:]).Scan(&hasRef)
		if errors.Is(err, pgx.ErrNoRows) {
			return meta.ErrNotExpected
		}
		if err != nil {
			return err
		}
		var cst string
		var csz int64
		err = q.QueryRow(ctx,
			`SELECT state, size FROM chunks WHERE user_id=$1 AND hash=$2`, userID, h[:]).Scan(&cst, &csz)
		if errors.Is(err, pgx.ErrNoRows) {
			return meta.ErrNotExpected
		}
		if err != nil {
			return err
		}
		switch cst {
		case meta.ChunkStored:
			return nil
		case meta.ChunkReserved:
			if csz != size {
				return fmt.Errorf("meta: chunk size %d, expected %d", size, csz)
			}
			tag, err := q.Exec(ctx,
				`UPDATE chunks SET state=$1 WHERE user_id=$2 AND hash=$3 AND state=$4`,
				meta.ChunkStored, userID, h[:], meta.ChunkReserved)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return nil
			}
			if _, err := q.Exec(ctx,
				`UPDATE usage SET used_bytes=used_bytes+$1, reserved_bytes=reserved_bytes-$2 WHERE user_id=$3`,
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
func (s *Store) release(ctx context.Context, q qtx, snapID, userID string) error {
	now := ns(s.now())
	rows, err := q.Query(ctx,
		`SELECT hash FROM snapshot_chunks WHERE snapshot_id=$1`, snapID)
	if err != nil {
		return err
	}
	var hashes [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		hashes = append(hashes, h)
	}
	rows.Close()
	var dUsed, dRes int64
	for _, h := range hashes {
		var rc int64
		var st string
		var size int64
		err := q.QueryRow(ctx,
			`UPDATE chunks SET refcount=refcount-1 WHERE user_id=$1 AND hash=$2 RETURNING refcount,state,size`,
			userID, h).Scan(&rc, &st, &size)
		if err != nil {
			return err
		}
		switch {
		case rc == 0 && st == meta.ChunkStored:
			if _, err := q.Exec(ctx,
				`UPDATE chunks SET zero_ref_since=$1 WHERE user_id=$2 AND hash=$3 AND refcount=0`, now, userID, h); err != nil {
				return err
			}
			dUsed += size
		case rc == 0 && st == meta.ChunkReserved:
			if _, err := q.Exec(ctx,
				`DELETE FROM chunks WHERE user_id=$1 AND hash=$2`, userID, h); err != nil {
				return err
			}
			dRes += size
		}
	}
	var mh []byte
	var msz int64
	err = q.QueryRow(ctx,
		`SELECT manifest_hash, manifest_size FROM snapshots WHERE id=$1`, snapID).Scan(&mh, &msz)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // snapshot already released
	}
	if err != nil {
		return err
	}
	var mrc int64
	err = q.QueryRow(ctx,
		`UPDATE manifests SET refcount=refcount-1 WHERE user_id=$1 AND hash=$2 RETURNING refcount`,
		userID, mh).Scan(&mrc)
	if err == nil && mrc == 0 {
		if _, err := q.Exec(ctx,
			`UPDATE manifests SET zero_ref_since=$1 WHERE user_id=$2 AND hash=$3`, now, userID, mh); err != nil {
			return err
		}
		dUsed += msz
	}
	if _, err := q.Exec(ctx, `DELETE FROM snapshot_chunks WHERE snapshot_id=$1`, snapID); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM snapshots WHERE id=$1`, snapID); err != nil {
		return err
	}
	if _, err := q.Exec(ctx,
		`UPDATE usage SET used_bytes=used_bytes-$1, reserved_bytes=reserved_bytes-$2 WHERE user_id=$3`,
		dUsed, dRes, userID); err != nil {
		return err
	}
	return nil
}

const snapCols = `id, user_id, app, slot, parent_id, device, label, state, manifest_hash, manifest_size, total_bytes, file_count, created_at, committed_at, expires_at`

func (s *Store) getSnap(ctx context.Context, q qtx, id string) (meta.Snapshot, error) {
	var sn meta.Snapshot
	var com, exp *int64
	var created int64
	var mh []byte
	err := q.QueryRow(ctx, `SELECT `+snapCols+` FROM snapshots WHERE id=$1`, id).
		Scan(&sn.ID, &sn.UserID, &sn.App, &sn.Slot, &sn.ParentID, &sn.Device, &sn.Label, &sn.State,
			&mh, &sn.ManifestSize, &sn.TotalBytes, &sn.FileCount, &created, &com, &exp)
	copy(sn.ManifestHash[:], mh)
	if errors.Is(err, pgx.ErrNoRows) {
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

func (s *Store) CommitSnapshot(ctx context.Context, userID, snapshotID string, o meta.CommitOptions) (meta.CommitResult, error) {
	var res meta.CommitResult
	err := s.wtx(ctx, func(q qtx) error {
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
		if err := q.QueryRow(ctx,
			`SELECT COUNT(*) FROM snapshot_chunks sc JOIN chunks c ON c.user_id=sc.user_id AND c.hash=sc.hash
			 WHERE sc.snapshot_id=$1 AND c.state <> $2`, snapshotID, meta.ChunkStored).Scan(&missing); err != nil {
			return err
		}
		if missing > 0 {
			return &meta.IncompleteError{Missing: int(missing)}
		}
		var head string
		err = q.QueryRow(ctx,
			`SELECT COALESCE(head_snapshot_id,'') FROM slots WHERE user_id=$1 AND app=$2 AND name=$3`,
			userID, sn.App, sn.Slot).Scan(&head)
		if errors.Is(err, pgx.ErrNoRows) {
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
		if _, err := q.Exec(ctx,
			`UPDATE snapshots SET state=$1, committed_at=$2, parent_id=$3 WHERE id=$4`,
			meta.StateCommitted, now, head, snapshotID); err != nil {
			return err
		}
		if _, err := q.Exec(ctx,
			`UPDATE slots SET head_snapshot_id=$1, updated_at=$2 WHERE user_id=$3 AND app=$4 AND name=$5`,
			snapshotID, now, userID, sn.App, sn.Slot); err != nil {
			return err
		}
		sn.State = meta.StateCommitted
		sn.ParentID = head
		ct := time.Unix(0, now).UTC()
		sn.CommittedAt = &ct
		res.Snapshot = sn
		rows, err := q.Query(ctx,
			`SELECT id, created_at FROM snapshots WHERE user_id=$1 AND app=$2 AND slot=$3 AND state=$4
			 ORDER BY created_at DESC, id DESC`, userID, sn.App, sn.Slot, meta.StateCommitted)
		if err != nil {
			return err
		}
		var pruneIDs []string
		idx := 0
		var cutoff int64
		if o.MaxAge > 0 {
			cutoff = now - int64(o.MaxAge)
		}
		for rows.Next() {
			var sid string
			var created int64
			if err := rows.Scan(&sid, &created); err != nil {
				rows.Close()
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
		rows.Close()
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

func (s *Store) AbortSnapshot(ctx context.Context, userID, snapshotID string) error {
	return s.wtx(ctx, func(q qtx) error {
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
	var n int
	err := s.wtx(ctx, func(q qtx) error {
		rows, err := q.Query(ctx,
			`SELECT id, user_id FROM snapshots WHERE state=$1 AND expires_at IS NOT NULL AND expires_at < $2 LIMIT $3`,
			meta.StatePending, ns(now), limit)
		if err != nil {
			return err
		}
		type pending struct{ id, uid string }
		var ps []pending
		for rows.Next() {
			var p pending
			if err := rows.Scan(&p.id, &p.uid); err != nil {
				rows.Close()
				return err
			}
			ps = append(ps, p)
		}
		rows.Close()
		for _, p := range ps {
			if err := s.release(ctx, q, p.id, p.uid); err != nil {
				return err
			}
		}
		n = len(ps)
		return nil
	})
	return n, err
}

func (s *Store) GetSnapshot(ctx context.Context, userID, app, slot, id string) (meta.Snapshot, error) {
	sn, err := s.getSnap(ctx, s.pool, id)
	if err != nil {
		return sn, err
	}
	if sn.UserID != userID || sn.App != app || sn.Slot != slot {
		return sn, meta.ErrNotFound
	}
	return sn, nil
}

func scanSnaps(rows pgx.Rows) ([]meta.Snapshot, error) {
	var out []meta.Snapshot
	for rows.Next() {
		var sn meta.Snapshot
		var com, exp *int64
		var created int64
		var mh []byte
		if err := rows.Scan(&sn.ID, &sn.UserID, &sn.App, &sn.Slot, &sn.ParentID, &sn.Device, &sn.Label, &sn.State,
			&mh, &sn.ManifestSize, &sn.TotalBytes, &sn.FileCount, &created, &com, &exp); err != nil {
			return nil, err
		}
		copy(sn.ManifestHash[:], mh)
		sn.CreatedAt = time.Unix(0, created).UTC()
		sn.CommittedAt = tm(com)
		sn.ExpiresAt = tm(exp)
		out = append(out, sn)
	}
	return out, rows.Err()
}

func (s *Store) ListSnapshots(ctx context.Context, userID, app, slot, cursor string, limit int) ([]meta.Snapshot, string, error) {
	cNS, cID, err := meta.DecodeCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	query := `SELECT ` + snapCols + ` FROM snapshots WHERE user_id=$1 AND app=$2 AND slot=$3`
	args := []any{userID, app, slot}
	if cursor != "" {
		query += ` AND (created_at < $4 OR (created_at = $4 AND id < $5))`
		args = append(args, cNS, cID)
	}
	query += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args)+1)
	args = append(args, limit+1)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	out, err := scanSnaps(rows)
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	var next string
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = meta.EncodeCursor(ns(last.CreatedAt), last.ID)
	}
	return out, next, nil
}

func (s *Store) DeleteSnapshot(ctx context.Context, userID, app, slot, id string) error {
	return s.wtx(ctx, func(q qtx) error {
		sn, err := s.getSnap(ctx, q, id)
		if err != nil {
			return err
		}
		if sn.UserID != userID || sn.App != app || sn.Slot != slot {
			return meta.ErrNotFound
		}
		if sn.State == meta.StateCommitted {
			var head string
			if err := q.QueryRow(ctx,
				`SELECT COALESCE(head_snapshot_id,'') FROM slots WHERE user_id=$1 AND app=$2 AND name=$3`,
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
	rows, err := s.pool.Query(ctx,
		`SELECT s.app, (SELECT COUNT(*) FROM slots sl WHERE sl.user_id=s.user_id AND sl.app=s.app), COUNT(*)
		 FROM snapshots s WHERE s.user_id=$1 GROUP BY s.app ORDER BY s.app`, userID)
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

func scanSlots(rows pgx.Rows) ([]meta.Slot, error) {
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

func (s *Store) ListSlots(ctx context.Context, userID, app string) ([]meta.Slot, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT user_id, app, name, COALESCE(head_snapshot_id,''), created_at, updated_at
		 FROM slots WHERE user_id=$1 AND app=$2 ORDER BY name`, userID, app)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSlots(rows)
}

func (s *Store) GetSlot(ctx context.Context, userID, app, slot string) (meta.Slot, error) {
	var sl meta.Slot
	var created, updated int64
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, app, name, COALESCE(head_snapshot_id,''), created_at, updated_at
		 FROM slots WHERE user_id=$1 AND app=$2 AND name=$3`, userID, app, slot).
		Scan(&sl.UserID, &sl.App, &sl.Name, &sl.HeadSnapshotID, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
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
	return s.wtx(ctx, func(q qtx) error {
		rows, err := q.Query(ctx,
			`SELECT id FROM snapshots WHERE user_id=$1 AND app=$2 AND slot=$3`, userID, app, slot)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			if err := s.release(ctx, q, id, userID); err != nil {
				return err
			}
		}
		tag, err := q.Exec(ctx,
			`DELETE FROM slots WHERE user_id=$1 AND app=$2 AND name=$3`, userID, app, slot)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
}

func (s *Store) Usage(ctx context.Context, userID string) (meta.Usage, error) {
	var u meta.Usage
	err := s.pool.QueryRow(ctx,
		`SELECT used_bytes, reserved_bytes FROM usage WHERE user_id=$1`, userID).Scan(&u.UsedBytes, &u.ReservedBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		u.UsedBytes, u.ReservedBytes = 0, 0
	} else if err != nil {
		return u, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM slots WHERE user_id=$1`, userID).Scan(&u.Slots); err != nil {
		return u, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM snapshots WHERE user_id=$1`, userID).Scan(&u.Snapshots); err != nil {
		return u, err
	}
	var quota *int64
	if err := s.pool.QueryRow(ctx, `SELECT quota_bytes FROM users WHERE id=$1`, userID).Scan(&quota); err == nil && quota != nil {
		u.QuotaBytes = *quota
	}
	return u, nil
}

func (s *Store) UnreferencedChunks(ctx context.Context, olderThan time.Time, limit int) ([]meta.ChunkRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT user_id, hash, size, state, zero_ref_since FROM chunks
		 WHERE refcount=0 AND zero_ref_since IS NOT NULL AND zero_ref_since < $1 ORDER BY zero_ref_since LIMIT $2`,
		ns(olderThan), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.ChunkRow
	for rows.Next() {
		var c meta.ChunkRow
		var zrs *int64
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
	err := s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx,
			`UPDATE chunks SET state=$1 WHERE user_id=$2 AND hash=$3 AND refcount=0`,
			meta.ChunkDeleting, userID, h[:])
		if err != nil {
			return err
		}
		ok = tag.RowsAffected() > 0
		return nil
	})
	return ok, err
}

func (s *Store) DeleteChunkRow(ctx context.Context, userID string, h api.Hash) (bool, error) {
	var ok bool
	err := s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx,
			`DELETE FROM chunks WHERE user_id=$1 AND hash=$2 AND refcount=0`, userID, h[:])
		if err != nil {
			return err
		}
		ok = tag.RowsAffected() > 0
		return nil
	})
	return ok, err
}

func (s *Store) UnreferencedManifests(ctx context.Context, olderThan time.Time, limit int) ([]meta.ManifestRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT user_id, hash, size, zero_ref_since FROM manifests
		 WHERE refcount=0 AND zero_ref_since IS NOT NULL AND zero_ref_since < $1 ORDER BY zero_ref_since LIMIT $2`,
		ns(olderThan), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.ManifestRow
	for rows.Next() {
		var m meta.ManifestRow
		var zrs *int64
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
	err := s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx,
			`DELETE FROM manifests WHERE user_id=$1 AND hash=$2 AND refcount=0`, userID, h[:])
		if err != nil {
			return err
		}
		ok = tag.RowsAffected() > 0
		return nil
	})
	return ok, err
}

func (s *Store) PurgedUsers(ctx context.Context, limit int) ([]meta.User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+userCols+` FROM users WHERE deleted_at IS NOT NULL ORDER BY deleted_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.User
	for rows.Next() {
		var u meta.User
		var quota, deleted, created *int64
		var disabled bool
		if err := rows.Scan(&u.ID, &u.Subject, &u.Tier, &quota, &disabled, &deleted, &created); err != nil {
			return nil, err
		}
		scanUserInto(&u, quota, deleted, created, &disabled)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) FinishPurge(ctx context.Context, userID string) error {
	return s.wtx(ctx, func(q qtx) error {
		rows, err := q.Query(ctx, `SELECT id FROM snapshots WHERE user_id=$1`, userID)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			if err := s.release(ctx, q, id, userID); err != nil {
				return err
			}
		}
		for _, stmt := range []string{
			`DELETE FROM tokens WHERE user_id=$1`,
			`DELETE FROM usage WHERE user_id=$1`,
			`DELETE FROM slots WHERE user_id=$1`,
			`DELETE FROM chunks WHERE user_id=$1`,
			`DELETE FROM manifests WHERE user_id=$1`,
			`DELETE FROM users WHERE id=$1`,
		} {
			if _, err := q.Exec(ctx, stmt, userID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	var ok bool
	err := s.wtx(ctx, func(q qtx) error {
		exp := ns(s.now().Add(ttl))
		tag, err := q.Exec(ctx,
			`INSERT INTO leases(name,holder,expires_at) VALUES($1,$2,$3)
			 ON CONFLICT(name) DO UPDATE SET holder=excluded.holder, expires_at=excluded.expires_at
			 WHERE leases.expires_at < $4 OR leases.holder = $5`,
			name, holder, exp, ns(s.now()), holder)
		if err != nil {
			return err
		}
		ok = tag.RowsAffected() > 0
		return nil
	})
	return ok, err
}

func (s *Store) Fsck(ctx context.Context, repair bool) (meta.FsckReport, error) {
	var rep meta.FsckReport
	err := s.wtx(ctx, func(q qtx) error {
		rows, err := q.Query(ctx,
			`SELECT sc.snapshot_id FROM snapshot_chunks sc
			 LEFT JOIN snapshots s ON s.id=sc.snapshot_id WHERE s.id IS NULL`)
		if err != nil {
			return err
		}
		var orphans []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			orphans = append(orphans, id)
			rep.OrphanRefs++
			rep.Issues = append(rep.Issues, "orphan snapshot_chunks for "+id)
		}
		rows.Close()
		if repair {
			for _, id := range orphans {
				if _, err := q.Exec(ctx, `DELETE FROM snapshot_chunks WHERE snapshot_id=$1`, id); err != nil {
					return err
				}
			}
		}
		type ck struct {
			uid    string
			h      []byte
			rc     int64
			expect int64
			size   int64
			state  string
			zrs    *int64
		}
		rows, err = q.Query(ctx,
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
				rows.Close()
				return err
			}
			cks = append(cks, c)
		}
		rows.Close()
		used := map[string]int64{}
		resvd := map[string]int64{}
		for _, c := range cks {
			if c.rc != c.expect || (c.expect == 0 && c.zrs == nil && c.state == meta.ChunkStored) {
				rep.Issues = append(rep.Issues, fmt.Sprintf("chunk refcount %d expected %d", c.rc, c.expect))
				rep.Refcounts++
				if repair {
					var zrs *int64
					if c.expect == 0 {
						if c.zrs != nil {
							zrs = c.zrs
						} else {
							v := ns(s.now())
							zrs = &v
						}
					}
					newState := c.state
					if c.expect > 0 && c.state == meta.ChunkDeleting {
						newState = meta.ChunkReserved
					}
					if _, err := q.Exec(ctx,
						`UPDATE chunks SET refcount=$1, state=$2, zero_ref_since=$3 WHERE user_id=$4 AND hash=$5`,
						c.expect, newState, zrs, c.uid, c.h); err != nil {
						return err
					}
					c.rc = c.expect
					c.state = newState
					c.zrs = zrs
				}
			}
			if c.state == meta.ChunkStored && c.rc > 0 {
				used[c.uid] += c.size
			}
			if c.state == meta.ChunkReserved {
				resvd[c.uid] += c.size
			}
		}
		rows, err = q.Query(ctx,
			`SELECT user_id, hash, size FROM chunks WHERE state=$1 AND refcount=0`, meta.ChunkReserved)
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
				rows.Close()
				return err
			}
			rks = append(rks, r)
			rep.Issues = append(rep.Issues, "reserved chunk with refcount 0")
		}
		rows.Close()
		if repair {
			for _, r := range rks {
				if _, err := q.Exec(ctx, `DELETE FROM chunks WHERE user_id=$1 AND hash=$2`, r.uid, r.h); err != nil {
					return err
				}
				resvd[r.uid] -= r.sz
			}
		}
		rows, err = q.Query(ctx,
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
				rows.Close()
				return err
			}
			mks = append(mks, m)
		}
		rows.Close()
		for _, m := range mks {
			if m.rc != m.expect {
				rep.Issues = append(rep.Issues, fmt.Sprintf("manifest refcount %d expected %d", m.rc, m.expect))
				rep.Refcounts++
				if repair {
					var zrs *int64
					if m.expect == 0 {
						v := ns(s.now())
						zrs = &v
					}
					if _, err := q.Exec(ctx,
						`UPDATE manifests SET refcount=$1, zero_ref_since=$2 WHERE user_id=$3 AND hash=$4`,
						m.expect, zrs, m.uid, m.h); err != nil {
						return err
					}
					m.rc = m.expect
				}
			}
			if m.rc > 0 {
				used[m.uid] += m.size
			}
		}
		rows, err = q.Query(ctx, `SELECT user_id, used_bytes, reserved_bytes FROM usage`)
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
				rows.Close()
				return err
			}
			urs = append(urs, u)
		}
		rows.Close()
		for _, u := range urs {
			eu, er := used[u.uid], resvd[u.uid]
			if u.used != eu || u.rv != er {
				rep.Issues = append(rep.Issues, fmt.Sprintf("usage %s used=%d/%d reserved=%d/%d", u.uid, u.used, eu, u.rv, er))
				rep.UsageFixed++
				if repair {
					if _, err := q.Exec(ctx,
						`UPDATE usage SET used_bytes=$1, reserved_bytes=$2 WHERE user_id=$3`, eu, er, u.uid); err != nil {
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

// GetVault implements meta.Store.
func (s *Store) GetVault(ctx context.Context, userID string) (meta.VaultRecord, error) {
	var r meta.VaultRecord
	err := s.pool.QueryRow(ctx,
		"SELECT header, kid, version FROM vault WHERE user_id = $1", userID).
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
		_, err := s.pool.Exec(ctx,
			"INSERT INTO vault (user_id, header, kid, version, updated_at) VALUES ($1, $2, $3, 1, $4)",
			userID, header, kid, now)
		if err != nil {
			return 0, meta.ErrVersionMismatch
		}
		return 1, nil
	}
	res, err := s.pool.Exec(ctx,
		"UPDATE vault SET header = $1, kid = $2, version = version + 1, updated_at = $3 WHERE user_id = $4 AND version = $5",
		header, kid, now, userID, *ifVersion)
	if err != nil {
		return 0, err
	}
	if res.RowsAffected() == 0 {
		return 0, meta.ErrVersionMismatch
	}
	return *ifVersion + 1, nil
}

// DeleteVault implements meta.Store.
func (s *Store) DeleteVault(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM vault WHERE user_id = $1", userID)
	return err
}
