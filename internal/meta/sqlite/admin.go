package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

func (s *Store) GetSettings(ctx context.Context) (map[string]meta.SettingRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT key, value, updated_at, updated_by FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]meta.SettingRow{}
	for rows.Next() {
		var r meta.SettingRow
		var at int64
		if err := rows.Scan(&r.Key, &r.Value, &at, &r.UpdatedBy); err != nil {
			return nil, err
		}
		r.UpdatedAt = time.Unix(0, at).UTC()
		out[r.Key] = r
	}
	return out, rows.Err()
}

func (s *Store) PutSetting(ctx context.Context, key, valueJSON, actor string) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO settings(key, value, updated_at, updated_by) VALUES(?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		key, valueJSON, ns(s.now()), actor)
	return err
}

func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM settings WHERE key=?`, key)
	return err
}

func (s *Store) CreateInvite(ctx context.Context, in meta.Invite) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO invites(id, code_hash, code_prefix, label, max_uses, uses, expires_at, created_by, created_at, revoked_at) VALUES(?,?,?,?,?,0,?,?,?,?)`,
		in.ID, in.CodeHash[:], in.CodePrefix, in.Label, in.MaxUses, nsPtr(in.ExpiresAt), in.CreatedBy, nsPtr(in.CreatedAt), nsPtr(in.RevokedAt))
	return err
}

func (s *Store) ListInvites(ctx context.Context) ([]meta.Invite, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, code_prefix, label, max_uses, uses, expires_at, created_by, created_at, revoked_at FROM invites ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.Invite
	for rows.Next() {
		var v meta.Invite
		var exp, rev, ca sql.NullInt64
		if err := rows.Scan(&v.ID, &v.CodePrefix, &v.Label, &v.MaxUses, &v.Uses, &exp, &v.CreatedBy, &ca, &rev); err != nil {
			return nil, err
		}
		v.ExpiresAt = tm(exp)
		v.RevokedAt = tm(rev)
		if ca.Valid {
			v.CreatedAt = tm(ca)
		}
		v.Status = "active"
		if v.RevokedAt != nil {
			v.Status = "revoked"
		} else if v.ExpiresAt != nil && v.ExpiresAt.Before(s.now()) {
			v.Status = "expired"
		} else if v.MaxUses > 0 && v.Uses >= v.MaxUses {
			v.Status = "exhausted"
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) RevokeInvite(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE invites SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, ns(s.now()), id)
	return err
}

func (s *Store) ConsumeInvite(ctx context.Context, codeHash [32]byte, userID, ip string) error {
	return s.wtx(ctx, func(q q) error {
		res, err := q.ExecContext(ctx, `UPDATE invites SET uses=uses+1 WHERE code_hash=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?) AND (max_uses=0 OR uses<max_uses)`,
			codeHash[:], ns(s.now()))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return meta.ErrInviteInvalid
		}
		_, err = q.ExecContext(ctx, `INSERT INTO invite_uses(invite_id, user_id, at, ip)
			SELECT id, ?, ?, ? FROM invites WHERE code_hash=?`, userID, ns(s.now()), ip, codeHash[:])
		return err
	})
}

func (s *Store) SetUserStatus(ctx context.Context, st meta.UserStatus) error {
	return s.wtx(ctx, func(q q) error {
		if _, err := q.ExecContext(ctx, `INSERT INTO user_status(user_id, state, reason, at, by, until) VALUES(?,?,?,?,?,?)
			ON CONFLICT(user_id) DO UPDATE SET state=excluded.state, reason=excluded.reason, at=excluded.at, by=excluded.by, until=excluded.until`,
			st.UserID, st.State, st.Reason, ns(st.At), st.By, nsPtr(st.Until)); err != nil {
			return err
		}
		_, err := q.ExecContext(ctx, `UPDATE users SET disabled=1 WHERE id=?`, st.UserID)
		return err
	})
}

func (s *Store) GetUserStatus(ctx context.Context, userID string) (meta.UserStatus, error) {
	var st meta.UserStatus
	var at, until sql.NullInt64
	err := s.r.QueryRowContext(ctx, `SELECT user_id, state, reason, at, by, until FROM user_status WHERE user_id=?`, userID).
		Scan(&st.UserID, &st.State, &st.Reason, &at, &st.By, &until)
	if err == sql.ErrNoRows {
		return st, meta.ErrNotFound
	}
	if err != nil {
		return st, err
	}
	st.At = time.Unix(0, at.Int64).UTC()
	st.Until = tm(until)
	return st, nil
}

func (s *Store) ClearUserStatus(ctx context.Context, userID string) error {
	return s.wtx(ctx, func(q q) error {
		if _, err := q.ExecContext(ctx, `DELETE FROM user_status WHERE user_id=?`, userID); err != nil {
			return err
		}
		_, err := q.ExecContext(ctx, `UPDATE users SET disabled=0 WHERE id=?`, userID)
		return err
	})
}

func (s *Store) ListUserStatuses(ctx context.Context, state string) ([]meta.UserStatus, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT user_id, state, reason, at, by, until FROM user_status WHERE state=?`, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.UserStatus
	for rows.Next() {
		var st meta.UserStatus
		var at, until sql.NullInt64
		if err := rows.Scan(&st.UserID, &st.State, &st.Reason, &at, &st.By, &until); err != nil {
			return nil, err
		}
		st.At = time.Unix(0, at.Int64).UTC()
		st.Until = tm(until)
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) ExpireBans(ctx context.Context, now time.Time) ([]string, error) {
	var ids []string
	err := s.wtx(ctx, func(q q) error {
		rows, err := q.QueryContext(ctx, `SELECT user_id FROM user_status WHERE until IS NOT NULL AND until<?`, ns(now))
		if err != nil {
			return err
		}
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
			if _, err := q.ExecContext(ctx, `DELETE FROM user_status WHERE user_id=?`, id); err != nil {
				return err
			}
			if _, err := q.ExecContext(ctx, `UPDATE users SET disabled=0 WHERE id=?`, id); err != nil {
				return err
			}
		}
		return nil
	})
	return ids, err
}

func (s *Store) AddIPBlock(ctx context.Context, b meta.IPBlock) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO ip_blocks(id, cidr, reason, created_by, created_at, expires_at) VALUES(?,?,?,?,?,?)`,
		b.ID, b.CIDR, b.Reason, b.CreatedBy, ns(b.CreatedAt), nsPtr(b.ExpiresAt))
	return err
}

func (s *Store) ListIPBlocks(ctx context.Context) ([]meta.IPBlock, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, cidr, reason, created_by, created_at, expires_at FROM ip_blocks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.IPBlock
	for rows.Next() {
		var b meta.IPBlock
		var ca, ex sql.NullInt64
		if err := rows.Scan(&b.ID, &b.CIDR, &b.Reason, &b.CreatedBy, &ca, &ex); err != nil {
			return nil, err
		}
		if ca.Valid {
			b.CreatedAt = time.Unix(0, ca.Int64).UTC()
		}
		b.ExpiresAt = tm(ex)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) DeleteIPBlock(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM ip_blocks WHERE id=?`, id)
	return err
}

func (s *Store) PurgeExpiredIPBlocks(ctx context.Context, now time.Time) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM ip_blocks WHERE expires_at IS NOT NULL AND expires_at<?`, ns(now))
	return err
}

func (s *Store) InsertAudit(ctx context.Context, ev []meta.AuditEvent) error {
	return s.wtx(ctx, func(q q) error {
		for _, e := range ev {
			if _, err := q.ExecContext(ctx, `INSERT INTO audit_events(id, at, actor_user_id, actor_label, action, target_type, target_id, ip, detail, request_id) VALUES(?,?,?,?,?,?,?,?,?,?)`,
				e.ID, ns(e.At), e.ActorID, e.ActorLabel, e.Action, e.TargetType, e.TargetID, e.IP, e.Detail, e.RequestID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ListAudit(ctx context.Context, f meta.AuditFilter, cursor string, limit int) ([]meta.AuditEvent, string, error) {
	if limit > 200 {
		limit = 200
	}
	var args []any
	q := `SELECT id, at, actor_user_id, actor_label, action, target_type, target_id, ip, detail, request_id FROM audit_events WHERE 1=1`
	if f.Action != "" {
		q += ` AND action=?`
		args = append(args, f.Action)
	}
	if f.ActorID != "" {
		q += ` AND actor_user_id=?`
		args = append(args, f.ActorID)
	}
	if f.TargetID != "" {
		q += ` AND target_id=?`
		args = append(args, f.TargetID)
	}
	if f.Query != "" {
		q += ` AND (action LIKE ? OR target_id LIKE ? OR detail LIKE ?)`
		like := "%" + f.Query + "%"
		args = append(args, like, like, like)
	}
	if !f.From.IsZero() {
		q += ` AND at>=?`
		args = append(args, ns(f.From))
	}
	if !f.To.IsZero() {
		q += ` AND at<=?`
		args = append(args, ns(f.To))
	}
	if cursor != "" {
		q += ` AND (at,id) < (SELECT at, id FROM audit_events WHERE id=?)`
		args = append(args, cursor)
	}
	q += ` ORDER BY at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []meta.AuditEvent
	for rows.Next() {
		var e meta.AuditEvent
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.ActorID, &e.ActorLabel, &e.Action, &e.TargetType, &e.TargetID, &e.IP, &e.Detail, &e.RequestID); err != nil {
			return nil, "", err
		}
		e.At = time.Unix(0, at).UTC()
		out = append(out, e)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[limit-1].ID
	}
	return out, next, rows.Err()
}

func (s *Store) PurgeAudit(ctx context.Context, before time.Time) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM audit_events WHERE at<?`, ns(before))
	return err
}

func (s *Store) AddStats(ctx context.Context, d []meta.StatsDelta) error {
	return s.wtx(ctx, func(q q) error {
		for _, r := range d {
			if _, err := q.ExecContext(ctx, `INSERT INTO stats_daily(day, signups, logins_ok, logins_failed, requests, errors_5xx, bytes_in, bytes_out, snapshots)
				VALUES(?,?,?,?,?,?,?,?,?)
				ON CONFLICT(day) DO UPDATE SET signups=signups+excluded.signups, logins_ok=logins_ok+excluded.logins_ok,
				logins_failed=logins_failed+excluded.logins_failed, requests=requests+excluded.requests,
				errors_5xx=errors_5xx+excluded.errors_5xx, bytes_in=bytes_in+excluded.bytes_in,
				bytes_out=bytes_out+excluded.bytes_out, snapshots=snapshots+excluded.snapshots`,
				r.Day, r.Signups, r.LoginsOK, r.LoginsFailed, r.Requests, r.Errors5xx, r.BytesIn, r.BytesOut, r.Snapshots); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) SetStatsGauges(ctx context.Context, day int, storageBytes, usersTotal, activeUsers int64) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO stats_daily(day, storage_bytes, users_total, active_users) VALUES(?,?,?,?)
		ON CONFLICT(day) DO UPDATE SET storage_bytes=excluded.storage_bytes, users_total=excluded.users_total, active_users=excluded.active_users`,
		day, storageBytes, usersTotal, activeUsers)
	return err
}

func (s *Store) TouchActivity(ctx context.Context, ud []meta.UserDay) error {
	return s.wtx(ctx, func(q q) error {
		for _, d := range ud {
			if _, err := q.ExecContext(ctx, `INSERT OR IGNORE INTO user_activity(user_id, day) VALUES(?,?)`, d.UserID, d.Day); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) StatsSeries(ctx context.Context, fromDay, toDay int) ([]meta.StatsRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT day, signups, logins_ok, logins_failed, requests, errors_5xx, bytes_in, bytes_out, snapshots, active_users, storage_bytes, users_total FROM stats_daily WHERE day>=? AND day<=? ORDER BY day`, fromDay, toDay)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byDay := map[int]meta.StatsRow{}
	for rows.Next() {
		var r meta.StatsRow
		if err := rows.Scan(&r.Day, &r.Signups, &r.LoginsOK, &r.LoginsFailed, &r.Requests, &r.Errors5xx, &r.BytesIn, &r.BytesOut, &r.Snapshots, &r.ActiveUsers, &r.Storage, &r.Users); err != nil {
			return nil, err
		}
		byDay[r.Day] = r
	}
	var out []meta.StatsRow
	for t := dayTime(fromDay); meta.BandwidthDay(t) <= toDay; t = t.AddDate(0, 0, 1) {
		k := meta.BandwidthDay(t)
		r := meta.StatsRow{Day: k}
		if v, ok := byDay[k]; ok {
			r = v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func dayTime(d int) time.Time {
	return time.Date(d/10000, time.Month(d/100%100), d%100, 0, 0, 0, 0, time.UTC)
}

func (s *Store) PurgeStats(ctx context.Context, beforeDay int) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM stats_daily WHERE day<?`, beforeDay)
	return err
}

func (s *Store) ListUsersAdmin(ctx context.Context, f meta.UserFilter, offset, limit int) ([]meta.AdminUserRow, int, error) {
	if limit > 100 {
		limit = 100
	}
	var args []any
	where := "1=1"
	if f.Tier != "" {
		where += " AND u.tier=?"
		args = append(args, f.Tier)
	}
	if f.Query != "" {
		where += " AND (u.id LIKE ? OR u.subject LIKE ? OR c.username LIKE ?)"
		like := "%" + strings.ToLower(f.Query) + "%"
		args = append(args, like, like, like)
	}
	switch f.State {
	case "disabled", "banned", "pending":
		where += " AND u.disabled=1"
		if f.State != "disabled" {
			where += " AND st.state=?"
			args = append(args, f.State)
		}
	case "active":
		where += " AND u.disabled=0"
	case "deleted":
		where += " AND u.deleted_at IS NOT NULL"
	}
	if f.AdminOnly {
		where += " AND c.admin=1"
	}
	order := "u.created_at"
	switch f.Sort {
	case "name":
		order = "c.username"
	case "used":
		order = "us.used_bytes"
	case "last_active":
		order = "la"
	}
	dir := "ASC"
	if f.Desc {
		dir = "DESC"
	}
	base := ` FROM users u
		LEFT JOIN credentials c ON c.user_id=u.id
		LEFT JOIN user_status st ON st.user_id=u.id
		LEFT JOIN usage us ON us.user_id=u.id
		LEFT JOIN (SELECT user_id, MAX(day) la FROM user_activity GROUP BY user_id) a ON a.user_id=u.id
		LEFT JOIN (SELECT user_id, COUNT(*) n FROM snapshots WHERE state='committed' GROUP BY user_id) sn ON sn.user_id=u.id
		LEFT JOIN (SELECT user_id, COUNT(*) sl FROM slots GROUP BY user_id) sl2 ON sl2.user_id=u.id
		LEFT JOIN (SELECT user_id, COUNT(*) tk FROM tokens WHERE revoked_at IS NULL GROUP BY user_id) tk2 ON tk2.user_id=u.id
		LEFT JOIN (SELECT user_id, COUNT(*) ws FROM web_sessions WHERE expires_at>` + `?` + ` GROUP BY user_id) ws2 ON ws2.user_id=u.id
		WHERE ` + where
	cntQ := `SELECT COUNT(DISTINCT u.id)` + base
	q := `SELECT u.id, u.subject, u.tier, u.quota_bytes, u.disabled, u.deleted_at, u.created_at,
		COALESCE(c.username,''), COALESCE(c.admin,0), COALESCE(c.totp_secret IS NOT NULL AND c.totp_secret != '',0),
		COALESCE(st.state,''), COALESCE(st.reason,''),
		COALESCE(us.used_bytes,0), COALESCE(us.reserved_bytes,0), a.la, COALESCE(sn.n,0), COALESCE(sl2.sl,0), COALESCE(tk2.tk,0), COALESCE(ws2.ws,0)
		` + base + ` ORDER BY ` + order + ` ` + dir + ` LIMIT ? OFFSET ?`
	var total int
	cargs := append([]any{ns(s.now())}, args...)
	if err := s.r.QueryRowContext(ctx, cntQ, cargs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args2 := append(append([]any{ns(s.now())}, args...), limit, offset)
	rows, err := s.r.QueryContext(ctx, q, args2...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []meta.AdminUserRow
	for rows.Next() {
		var r meta.AdminUserRow
		var la sql.NullInt64
		var ca sql.NullInt64
		var webAdmin, totp int
		if err := rows.Scan(&r.User.ID, &r.User.Subject, &r.User.Tier, &r.User.QuotaBytes, &r.User.Disabled, &r.User.DeletedAt, &ca,
			&r.Username, &webAdmin, &totp, &r.Status, &r.StatusReason,
			&r.UsedBytes, &r.ReservedBytes, &la, &r.Snapshots, &r.Slots, &r.Tokens, &r.Sessions); err != nil {
			return nil, 0, err
		}
		if ca.Valid {
			t0 := time.Unix(0, ca.Int64).UTC()
			r.User.CreatedAt = t0
		}
		r.WebAdmin = webAdmin != 0
		r.TOTP = totp != 0
		if la.Valid {
			t := dayTime(int(la.Int64))
			r.LastActive = &t
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *Store) AdminTotals(ctx context.Context) (meta.AdminTotals, error) {
	var t meta.AdminTotals
	err := s.r.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM users WHERE deleted_at IS NULL),
		(SELECT COUNT(*) FROM users WHERE disabled=1 AND deleted_at IS NULL),
		(SELECT COUNT(*) FROM user_status WHERE state='pending'),
		(SELECT COUNT(*) FROM user_status WHERE state='banned'),
		(SELECT COUNT(*) FROM users WHERE deleted_at IS NOT NULL),
		(SELECT COALESCE(SUM(used_bytes),0) FROM usage),
		(SELECT COUNT(*) FROM snapshots WHERE state='committed'),
		(SELECT COUNT(*) FROM slots),
		(SELECT COUNT(DISTINCT app) FROM slots),
		(SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL),
		(SELECT COUNT(*) FROM web_sessions WHERE expires_at>?),
		(SELECT COUNT(*) FROM snapshots WHERE state='pending')`,
		ns(s.now())).Scan(&t.Users, &t.Disabled, &t.PendingUsers, &t.Banned, &t.Deleted,
		&t.UsedBytes, &t.Snapshots, &t.Slots, &t.Apps, &t.ActiveTokens, &t.ActiveSessions, &t.PendingSnapshots)
	return t, err
}

func (s *Store) TopUsersByStorage(ctx context.Context, n int) ([]meta.AdminUserRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT u.id, u.subject, COALESCE(us.used_bytes,0) FROM users u
		LEFT JOIN usage us ON us.user_id=u.id WHERE u.deleted_at IS NULL ORDER BY us.used_bytes DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.AdminUserRow
	for rows.Next() {
		var r meta.AdminUserRow
		if err := rows.Scan(&r.User.ID, &r.User.Subject, &r.UsedBytes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) TopApps(ctx context.Context, n int) ([]meta.AppBytes, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT s.app, COUNT(*), COALESCE(SUM(COALESCE(sn.total_bytes,0)),0), COUNT(sn.id)
		FROM slots s LEFT JOIN snapshots sn ON sn.id=s.head_snapshot_id AND sn.state='committed'
		GROUP BY s.app ORDER BY 3 DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.AppBytes
	for rows.Next() {
		var a meta.AppBytes
		if err := rows.Scan(&a.App, &a.Slots, &a.Bytes, &a.Snapshots); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
