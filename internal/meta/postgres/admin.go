package postgres

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetSettings(ctx context.Context) (map[string]meta.SettingRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value, updated_at, updated_by FROM settings`)
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
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `INSERT INTO settings(key, value, updated_at, updated_by) VALUES($1,$2,$3,$4)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
			key, valueJSON, ns(s.now()), actor)
		return err
	})
}

func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `DELETE FROM settings WHERE key=$1`, key)
		return err
	})
}

func (s *Store) CreateInvite(ctx context.Context, in meta.Invite) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `INSERT INTO invites(id, code_hash, code_prefix, label, max_uses, uses, expires_at, created_by, created_at, revoked_at) VALUES($1,$2,$3,$4,$5,0,$6,$7,$8,$9)`,
			in.ID, in.CodeHash[:], in.CodePrefix, in.Label, in.MaxUses, nsPtr(in.ExpiresAt), in.CreatedBy, nsPtr(in.CreatedAt), nsPtr(in.RevokedAt))
		return err
	})
}

func (s *Store) ListInvites(ctx context.Context) ([]meta.Invite, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, code_prefix, label, max_uses, uses, expires_at, created_by, created_at, revoked_at FROM invites ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.Invite
	for rows.Next() {
		var v meta.Invite
		var exp, rev, ca *int64
		if err := rows.Scan(&v.ID, &v.CodePrefix, &v.Label, &v.MaxUses, &v.Uses, &exp, &v.CreatedBy, &ca, &rev); err != nil {
			return nil, err
		}
		v.ExpiresAt = tm(exp)
		v.RevokedAt = tm(rev)
		if ca != nil {
			t0 := time.Unix(0, *ca).UTC()
			v.CreatedAt = &t0
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
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `UPDATE invites SET revoked_at=$1 WHERE id=$2 AND revoked_at IS NULL`, ns(s.now()), id)
		return err
	})
}

func (s *Store) ConsumeInvite(ctx context.Context, codeHash [32]byte, userID, ip string) error {
	return s.wtx(ctx, func(q qtx) error {
		res, err := q.Exec(ctx, `UPDATE invites SET uses=uses+1 WHERE code_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$2) AND (max_uses=0 OR uses<max_uses)`,
			codeHash[:], ns(s.now()))
		if err != nil {
			return err
		}
		if n := res.RowsAffected(); n == 0 {
			return meta.ErrInviteInvalid
		}
		_, err = q.Exec(ctx, `INSERT INTO invite_uses(invite_id, user_id, at, ip)
			SELECT id, $1, $2, $3 FROM invites WHERE code_hash=$4`, userID, ns(s.now()), ip, codeHash[:])
		return err
	})
}

func (s *Store) SetUserStatus(ctx context.Context, st meta.UserStatus) error {
	return s.wtx(ctx, func(q qtx) error {
		if _, err := q.Exec(ctx, `INSERT INTO user_status(user_id, state, reason, at, by, until) VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT(user_id) DO UPDATE SET state=excluded.state, reason=excluded.reason, at=excluded.at, by=excluded.by, until=excluded.until`,
			st.UserID, st.State, st.Reason, ns(st.At), st.By, nsPtr(st.Until)); err != nil {
			return err
		}
		_, err := q.Exec(ctx, `UPDATE users SET disabled=true WHERE id=$1`, st.UserID)
		return err
	})
}

func (s *Store) GetUserStatus(ctx context.Context, userID string) (meta.UserStatus, error) {
	var st meta.UserStatus
	var at, until *int64
	err := s.pool.QueryRow(ctx, `SELECT user_id, state, reason, at, by, until FROM user_status WHERE user_id=$1`, userID).
		Scan(&st.UserID, &st.State, &st.Reason, &at, &st.By, &until)
	if err == pgx.ErrNoRows {
		return st, meta.ErrNotFound
	}
	if err != nil {
		return st, err
	}
	if at != nil {
		st.At = time.Unix(0, *at).UTC()
	}
	st.Until = tm(until)
	return st, nil
}

func (s *Store) ClearUserStatus(ctx context.Context, userID string) error {
	return s.wtx(ctx, func(q qtx) error {
		if _, err := q.Exec(ctx, `DELETE FROM user_status WHERE user_id=$1`, userID); err != nil {
			return err
		}
		_, err := q.Exec(ctx, `UPDATE users SET disabled=false WHERE id=$1`, userID)
		return err
	})
}

func (s *Store) ListUserStatuses(ctx context.Context, state string) ([]meta.UserStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_id, state, reason, at, by, until FROM user_status WHERE state=$1`, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.UserStatus
	for rows.Next() {
		var st meta.UserStatus
		var at, until *int64
		if err := rows.Scan(&st.UserID, &st.State, &st.Reason, &at, &st.By, &until); err != nil {
			return nil, err
		}
		if at != nil {
			st.At = time.Unix(0, *at).UTC()
		}
		st.Until = tm(until)
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) ExpireBans(ctx context.Context, now time.Time) ([]string, error) {
	var ids []string
	err := s.wtx(ctx, func(q qtx) error {
		rows, err := q.Query(ctx, `SELECT user_id FROM user_status WHERE until IS NOT NULL AND until<$1`, ns(now))
		if err != nil {
			return err
		}
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
			if _, err := q.Exec(ctx, `DELETE FROM user_status WHERE user_id=$1`, id); err != nil {
				return err
			}
			if _, err := q.Exec(ctx, `UPDATE users SET disabled=false WHERE id=$1`, id); err != nil {
				return err
			}
		}
		return nil
	})
	return ids, err
}

func (s *Store) AddIPBlock(ctx context.Context, b meta.IPBlock) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `INSERT INTO ip_blocks(id, cidr, reason, created_by, created_at, expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
			b.ID, b.CIDR, b.Reason, b.CreatedBy, ns(b.CreatedAt), nsPtr(b.ExpiresAt))
		return err
	})
}

func (s *Store) ListIPBlocks(ctx context.Context) ([]meta.IPBlock, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, cidr, reason, created_by, created_at, expires_at FROM ip_blocks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.IPBlock
	for rows.Next() {
		var b meta.IPBlock
		var ca, ex *int64
		if err := rows.Scan(&b.ID, &b.CIDR, &b.Reason, &b.CreatedBy, &ca, &ex); err != nil {
			return nil, err
		}
		if ca != nil {
			b.CreatedAt = time.Unix(0, *ca).UTC()
		}
		b.ExpiresAt = tm(ex)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) DeleteIPBlock(ctx context.Context, id string) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `DELETE FROM ip_blocks WHERE id=$1`, id)
		return err
	})
}

func (s *Store) PurgeExpiredIPBlocks(ctx context.Context, now time.Time) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `DELETE FROM ip_blocks WHERE expires_at IS NOT NULL AND expires_at<$1`, ns(now))
		return err
	})
}

func (s *Store) InsertAudit(ctx context.Context, ev []meta.AuditEvent) error {
	return s.wtx(ctx, func(q qtx) error {
		for _, e := range ev {
			if _, err := q.Exec(ctx, `INSERT INTO audit_events(id, at, actor_user_id, actor_label, action, target_type, target_id, ip, detail, request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
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
	n := 0
	next := func() string { n++; return "$" + itoa2(n) }
	q := `SELECT id, at, actor_user_id, actor_label, action, target_type, target_id, ip, detail, request_id FROM audit_events WHERE 1=1`
	if f.Action != "" {
		args = append(args, f.Action)
		q += ` AND action=` + next()
	}
	if f.ActorID != "" {
		args = append(args, f.ActorID)
		q += ` AND actor_user_id=` + next()
	}
	if f.TargetID != "" {
		args = append(args, f.TargetID)
		q += ` AND target_id=` + next()
	}
	if f.Query != "" {
		like := "%" + f.Query + "%"
		a, b, c := next(), next(), next()
		args = append(args, like, like, like)
		q += ` AND (action LIKE ` + a + ` OR target_id LIKE ` + b + ` OR detail LIKE ` + c + `)`
	}
	if !f.From.IsZero() {
		args = append(args, ns(f.From))
		q += ` AND at>=` + next()
	}
	if !f.To.IsZero() {
		args = append(args, ns(f.To))
		q += ` AND at<=` + next()
	}
	if cursor != "" {
		args = append(args, cursor)
		q += ` AND (at,id) < (SELECT at, id FROM audit_events WHERE id=` + next() + `)`
	}
	args = append(args, limit+1)
	q += ` ORDER BY at DESC, id DESC LIMIT ` + next()
	rows, err := s.pool.Query(ctx, q, args...)
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
	next2 := ""
	if len(out) > limit {
		out = out[:limit]
		next2 = out[limit-1].ID
	}
	return out, next2, rows.Err()
}

func itoa2(n int) string {
	return strconv.Itoa(n)
}

func (s *Store) PurgeAudit(ctx context.Context, before time.Time) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `DELETE FROM audit_events WHERE at<$1`, ns(before))
		return err
	})
}

func (s *Store) AddStats(ctx context.Context, d []meta.StatsDelta) error {
	return s.wtx(ctx, func(q qtx) error {
		for _, r := range d {
			if _, err := q.Exec(ctx, `INSERT INTO stats_daily(day, signups, logins_ok, logins_failed, requests, errors_5xx, bytes_in, bytes_out, snapshots)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
				ON CONFLICT(day) DO UPDATE SET signups=stats_daily.signups+excluded.signups, logins_ok=stats_daily.logins_ok+excluded.logins_ok,
				logins_failed=stats_daily.logins_failed+excluded.logins_failed, requests=stats_daily.requests+excluded.requests,
				errors_5xx=stats_daily.errors_5xx+excluded.errors_5xx, bytes_in=stats_daily.bytes_in+excluded.bytes_in,
				bytes_out=stats_daily.bytes_out+excluded.bytes_out, snapshots=stats_daily.snapshots+excluded.snapshots`,
				r.Day, r.Signups, r.LoginsOK, r.LoginsFailed, r.Requests, r.Errors5xx, r.BytesIn, r.BytesOut, r.Snapshots); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) SetStatsGauges(ctx context.Context, day int, storageBytes, usersTotal, activeUsers int64) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `INSERT INTO stats_daily(day, storage_bytes, users_total, active_users) VALUES($1,$2,$3,$4)
			ON CONFLICT(day) DO UPDATE SET storage_bytes=excluded.storage_bytes, users_total=excluded.users_total, active_users=excluded.active_users`,
			day, storageBytes, usersTotal, activeUsers)
		return err
	})
}

func (s *Store) TouchActivity(ctx context.Context, ud []meta.UserDay) error {
	return s.wtx(ctx, func(q qtx) error {
		for _, d := range ud {
			if _, err := q.Exec(ctx, `INSERT INTO user_activity(user_id, day) VALUES($1,$2) ON CONFLICT(user_id, day) DO NOTHING`, d.UserID, d.Day); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) StatsSeries(ctx context.Context, fromDay, toDay int) ([]meta.StatsRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT day, signups, logins_ok, logins_failed, requests, errors_5xx, bytes_in, bytes_out, snapshots, active_users, storage_bytes, users_total FROM stats_daily WHERE day>=$1 AND day<=$2 ORDER BY day`, fromDay, toDay)
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
	for t := time.Date(fromDay/10000, time.Month(fromDay/100%100), fromDay%100, 0, 0, 0, 0, time.UTC); meta.BandwidthDay(t) <= toDay; t = t.AddDate(0, 0, 1) {
		k := meta.BandwidthDay(t)
		r := meta.StatsRow{Day: k}
		if v, ok := byDay[k]; ok {
			r = v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) PurgeStats(ctx context.Context, beforeDay int) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `DELETE FROM stats_daily WHERE day<$1`, beforeDay)
		return err
	})
}

func (s *Store) ListUsersAdmin(ctx context.Context, f meta.UserFilter, offset, limit int) ([]meta.AdminUserRow, int, error) {
	if limit > 100 {
		limit = 100
	}
	var args []any
	n := 0
	next := func() string { n++; return "$" + itoa2(n) }
	where := "1=1"
	if f.Tier != "" {
		where += " AND u.tier=" + next()
		args = append(args, f.Tier)
	}
	if f.Query != "" {
		like := "%" + strings.ToLower(f.Query) + "%"
		a, b, c := next(), next(), next()
		where += " AND (u.id LIKE " + a + " OR u.subject LIKE " + b + " OR c.username LIKE " + c + ")"
		args = append(args, like, like, like)
	}
	switch f.State {
	case "disabled", "banned", "pending":
		where += " AND u.disabled"
		if f.State != "disabled" {
			where += " AND st.state=" + next()
			args = append(args, f.State)
		}
	case "active":
		where += " AND NOT u.disabled"
	case "deleted":
		where += " AND u.deleted_at IS NOT NULL"
	}
	if f.AdminOnly {
		where += " AND c.admin"
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
	nowPH := next()
	base := ` FROM users u
		LEFT JOIN credentials c ON c.user_id=u.id
		LEFT JOIN user_status st ON st.user_id=u.id
		LEFT JOIN usage us ON us.user_id=u.id
		LEFT JOIN (SELECT user_id, MAX(day) la FROM user_activity GROUP BY user_id) a ON a.user_id=u.id
		LEFT JOIN (SELECT user_id, COUNT(*) n FROM snapshots WHERE state='committed' GROUP BY user_id) sn ON sn.user_id=u.id
		LEFT JOIN (SELECT user_id, COUNT(*) sl FROM slots GROUP BY user_id) sl2 ON sl2.user_id=u.id
		LEFT JOIN (SELECT user_id, COUNT(*) tk FROM tokens WHERE revoked_at IS NULL GROUP BY user_id) tk2 ON tk2.user_id=u.id
		LEFT JOIN (SELECT user_id, COUNT(*) ws FROM web_sessions WHERE expires_at>` + nowPH + ` GROUP BY user_id) ws2 ON ws2.user_id=u.id
		WHERE ` + where
	var total int
	cargs := append([]any{ns(s.now())}, args...)
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(DISTINCT u.id)`+base, cargs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limitPH, offsetPH := next(), next()
	q := `SELECT u.id, u.subject, u.tier, u.quota_bytes, u.disabled, u.deleted_at, u.created_at,
		COALESCE(c.username,''), COALESCE(c.admin,false), (c.totp_secret IS NOT NULL AND c.totp_secret != ''),
		COALESCE(st.state,''), COALESCE(st.reason,''),
		COALESCE(us.used_bytes,0), COALESCE(us.reserved_bytes,0), a.la, COALESCE(sn.n,0), COALESCE(sl2.sl,0), COALESCE(tk2.tk,0), COALESCE(ws2.ws,0)
		` + base + ` ORDER BY ` + order + ` ` + dir + ` LIMIT ` + limitPH + ` OFFSET ` + offsetPH
	args2 := append(append([]any{ns(s.now())}, args...), limit, offset)
	rows, err := s.pool.Query(ctx, q, args2...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []meta.AdminUserRow
	for rows.Next() {
		var r meta.AdminUserRow
		var la, ca, del *int64
		if err := rows.Scan(&r.User.ID, &r.User.Subject, &r.User.Tier, &r.User.QuotaBytes, &r.User.Disabled, &del, &ca,
			&r.Username, &r.WebAdmin, &r.TOTP, &r.Status, &r.StatusReason,
			&r.UsedBytes, &r.ReservedBytes, &la, &r.Snapshots, &r.Slots, &r.Tokens, &r.Sessions); err != nil {
			return nil, 0, err
		}
		if ca != nil {
			r.User.CreatedAt = time.Unix(0, *ca).UTC()
		}
		if del != nil {
			t := time.Unix(0, *del).UTC()
			r.User.DeletedAt = &t
		}
		if la != nil {
			t := time.Date(int(*la)/10000, time.Month(*la/100%100), int(*la)%100, 0, 0, 0, 0, time.UTC)
			r.LastActive = &t
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *Store) AdminTotals(ctx context.Context) (meta.AdminTotals, error) {
	var t meta.AdminTotals
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT COUNT(*) FROM users WHERE deleted_at IS NULL),
		(SELECT COUNT(*) FROM users WHERE disabled AND deleted_at IS NULL),
		(SELECT COUNT(*) FROM user_status WHERE state='pending'),
		(SELECT COUNT(*) FROM user_status WHERE state='banned'),
		(SELECT COUNT(*) FROM users WHERE deleted_at IS NOT NULL),
		(SELECT COALESCE(SUM(used_bytes),0) FROM usage),
		(SELECT COUNT(*) FROM snapshots WHERE state='committed'),
		(SELECT COUNT(*) FROM slots),
		(SELECT COUNT(DISTINCT app) FROM slots),
		(SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL),
		(SELECT COUNT(*) FROM web_sessions WHERE expires_at>$1),
		(SELECT COUNT(*) FROM snapshots WHERE state='pending')`,
		ns(s.now())).Scan(&t.Users, &t.Disabled, &t.PendingUsers, &t.Banned, &t.Deleted,
		&t.UsedBytes, &t.Snapshots, &t.Slots, &t.Apps, &t.ActiveTokens, &t.ActiveSessions, &t.PendingSnapshots)
	return t, err
}

func (s *Store) TopUsersByStorage(ctx context.Context, n int) ([]meta.AdminUserRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT u.id, u.subject, COALESCE(us.used_bytes,0) FROM users u
		LEFT JOIN usage us ON us.user_id=u.id WHERE u.deleted_at IS NULL ORDER BY us.used_bytes DESC LIMIT $1`, n)
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
	rows, err := s.pool.Query(ctx, `SELECT s.app, COUNT(*), COALESCE(SUM(COALESCE(sn.total_bytes,0)),0), COUNT(sn.id)
		FROM slots s LEFT JOIN snapshots sn ON sn.id=s.head_snapshot_id AND sn.state='committed'
		GROUP BY s.app ORDER BY 3 DESC LIMIT $1`, n)
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
