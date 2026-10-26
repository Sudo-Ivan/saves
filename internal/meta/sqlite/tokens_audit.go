package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

func (s *Store) UpdateToken(ctx context.Context, id string, p meta.TokenPatch) error {
	sets, args := []string{}, []any{}
	if p.Name != nil {
		sets = append(sets, "name=?")
		args = append(args, *p.Name)
	}
	if p.ExpiresAt != nil {
		sets = append(sets, "expires_at=?")
		args = append(args, nsPtr(*p.ExpiresAt))
	}
	if p.CIDRs != nil {
		sets = append(sets, "allowed_cidrs=?")
		args = append(args, strings.Join(*p.CIDRs, ","))
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	res, err := s.w.ExecContext(ctx, `UPDATE tokens SET `+strings.Join(sets, ",")+` WHERE id=?`, args...) // #nosec G202 -- column names are fixed in code, values are bound
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return meta.ErrNotFound
	}
	return nil
}

func (s *Store) InsertTokenEvent(ctx context.Context, e meta.TokenEvent) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO token_events(id, token_id, user_id, at, kind, ip, actor_user_id, user_agent, request_id, detail) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.TokenID, e.UserID, ns(e.At), e.Kind, e.IP, e.ActorID, e.UserAgent, e.RequestID, e.Detail)
	return err
}

func (s *Store) UpsertTokenUsage(ctx context.Context, b []meta.UsageRow) ([]meta.UsagePair, error) {
	var pairs []meta.UsagePair
	err := s.wtx(ctx, func(q q) error {
		pairs = pairs[:0]
		seen := map[string]bool{}
		tokenSeen := map[string]bool{}
		for _, r := range b {
			if _, ok := tokenSeen[r.TokenID]; !ok {
				var n int
				if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage WHERE token_id=?`, r.TokenID).Scan(&n); err != nil {
					return err
				}
				tokenSeen[r.TokenID] = n > 0
			}
			key := r.TokenID + "|" + r.IP
			if !seen[key] {
				seen[key] = true
				var n int
				if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage WHERE token_id=? AND ip=?`, r.TokenID, r.IP).Scan(&n); err != nil {
					return err
				}
				if n == 0 {
					pairs = append(pairs, meta.UsagePair{TokenID: r.TokenID, IP: r.IP, First: !tokenSeen[r.TokenID]})
					tokenSeen[r.TokenID] = true
				}
			}
			if _, err := q.ExecContext(ctx, `INSERT INTO token_usage(token_id, bucket, ip, requests, last_seen, user_agent) VALUES(?,?,?,?,?,?)
				ON CONFLICT(token_id, bucket, ip) DO UPDATE SET requests=requests+excluded.requests,
				last_seen=excluded.last_seen, user_agent=excluded.user_agent`,
				r.TokenID, ns(r.Bucket), r.IP, r.Requests, ns(r.LastSeen), r.UserAgent); err != nil {
				return err
			}
		}
		return nil
	})
	return pairs, err
}

func (s *Store) ListTokenEvents(ctx context.Context, tokenID, kind, cursor string, limit int) ([]meta.TokenEvent, string, error) {
	curNS, curID, err := meta.DecodeCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	q := `SELECT id, token_id, user_id, at, kind, ip, actor_user_id, user_agent, request_id, detail FROM token_events WHERE token_id=?`
	args := []any{tokenID}
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	if cursor != "" {
		q += ` AND (at<? OR (at=? AND id<?))`
		args = append(args, curNS, curNS, curID)
	}
	q += ` ORDER BY at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []meta.TokenEvent
	for rows.Next() {
		var e meta.TokenEvent
		var at int64
		if err := rows.Scan(&e.ID, &e.TokenID, &e.UserID, &at, &e.Kind, &e.IP, &e.ActorID, &e.UserAgent, &e.RequestID, &e.Detail); err != nil {
			return nil, "", err
		}
		e.At = time.Unix(0, at).UTC()
		out = append(out, e)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = meta.EncodeCursor(ns(last.At), last.ID)
	}
	return out, next, rows.Err()
}

func (s *Store) TokenStats(ctx context.Context, tokenID string) (meta.TokenStats, error) {
	var st meta.TokenStats
	st.Denied = map[string]int64{}
	now := s.now()
	hr := func(d time.Duration) int64 { return ns(now.Add(-d).UTC().Truncate(time.Hour)) }
	cut24, cut7, cut30 := hr(24*time.Hour), hr(7*24*time.Hour), hr(30*24*time.Hour)
	err := s.r.QueryRowContext(ctx, `SELECT COALESCE(SUM(requests),0), COALESCE(SUM(CASE WHEN bucket>=? THEN requests ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN bucket>=? THEN requests ELSE 0 END),0), COALESCE(SUM(CASE WHEN bucket>=? THEN requests ELSE 0 END),0)
		FROM token_usage WHERE token_id=?`, cut24, cut7, cut30, tokenID).Scan(&st.Total, &st.Last24h, &st.Last7d, &st.Last30d)
	if err != nil {
		return st, err
	}
	// daily series last 30 days, zero filled
	dayStart := now.UTC().Truncate(24 * time.Hour)
	st.Daily = make([]int64, 30)
	rows, err := s.r.QueryContext(ctx, `SELECT bucket, SUM(requests) FROM token_usage WHERE token_id=? AND bucket>=? GROUP BY bucket`,
		tokenID, ns(dayStart.Add(-29*24*time.Hour)))
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var b, c int64
		if err := rows.Scan(&b, &c); err != nil {
			_ = rows.Close()
			return st, err
		}
		d := time.Unix(0, b).UTC().Truncate(24 * time.Hour)
		i := int(d.Sub(dayStart.Add(-29*24*time.Hour)).Hours() / 24)
		if i >= 0 && i < 30 {
			st.Daily[i] = c
		}
	}
	_ = rows.Close()
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(DISTINCT ip) FROM token_usage WHERE token_id=? AND bucket>=?`,
		tokenID, cut30).Scan(&st.UniqueIPs30d); err != nil {
		return st, err
	}
	rows, err = s.r.QueryContext(ctx, `SELECT ip, SUM(requests), MAX(last_seen), MAX(user_agent) FROM token_usage WHERE token_id=? AND bucket>=? GROUP BY ip ORDER BY SUM(requests) DESC LIMIT 10`,
		tokenID, cut30)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var c meta.IPCount
		var ls int64
		if err := rows.Scan(&c.IP, &c.Requests, &ls, &c.UserAgent); err != nil {
			_ = rows.Close()
			return st, err
		}
		t := time.Unix(0, ls).UTC()
		c.LastSeen = t
		st.TopIPs = append(st.TopIPs, c)
	}
	_ = rows.Close()
	rows, err = s.r.QueryContext(ctx, `SELECT kind, COUNT(*) FROM token_events WHERE token_id=? AND at>=? AND kind LIKE 'denied_%' GROUP BY kind`,
		tokenID, cut30)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			_ = rows.Close()
			return st, err
		}
		st.Denied[k] = n
	}
	_ = rows.Close()
	var f, l sql.NullInt64
	_ = s.r.QueryRowContext(ctx, `SELECT MIN(bucket), MAX(last_seen) FROM token_usage WHERE token_id=?`, tokenID).Scan(&f, &l)
	if f.Valid {
		t := time.Unix(0, f.Int64).UTC()
		st.FirstUse = &t
	}
	if l.Valid {
		t := time.Unix(0, l.Int64).UTC()
		st.LastUse = &t
	}
	return st, nil
}

func (s *Store) PurgeTokenAudit(ctx context.Context, before time.Time) error {
	if _, err := s.w.ExecContext(ctx, `DELETE FROM token_events WHERE at<?`, ns(before)); err != nil {
		return err
	}
	_, err := s.w.ExecContext(ctx, `DELETE FROM token_usage WHERE bucket<?`, ns(before))
	return err
}
