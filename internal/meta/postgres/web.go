// SPDX-License-Identifier: 0BSD

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

const credCols = `user_id, username, password_hash, admin, must_change, totp_secret, totp_enabled, totp_last_step, created_at, updated_at` // #nosec G101 -- column list or usage text, not a credential

func scanCred(row pgx.Row) (meta.WebCredential, error) {
	var c meta.WebCredential
	var created, updated int64
	err := row.Scan(&c.UserID, &c.Username, &c.PasswordHash, &c.Admin, &c.MustChange,
		&c.TOTPSecret, &c.TOTPEnabled, &c.TOTPLastStep, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, meta.ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.CreatedAt = time.Unix(0, created).UTC()
	c.UpdatedAt = time.Unix(0, updated).UTC()
	return c, nil
}

func (s *Store) GetCredentialByUsername(ctx context.Context, username string) (meta.WebCredential, error) {
	return scanCred(s.pool.QueryRow(ctx,
		`SELECT `+credCols+` FROM credentials WHERE username=$1`, strings.ToLower(username)))
}

func (s *Store) GetCredential(ctx context.Context, userID string) (meta.WebCredential, error) {
	return scanCred(s.pool.QueryRow(ctx,
		`SELECT `+credCols+` FROM credentials WHERE user_id=$1`, userID))
}

func (s *Store) CreateCredential(ctx context.Context, c meta.WebCredential) error {
	now := s.now()
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `INSERT INTO credentials(`+credCols+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			c.UserID, strings.ToLower(c.Username), c.PasswordHash, c.Admin, c.MustChange,
			c.TOTPSecret, c.TOTPEnabled, c.TOTPLastStep, ns(now), ns(now))
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return meta.ErrExists
		}
		return err
	})
}

func (s *Store) UpdateCredential(ctx context.Context, userID string, p meta.CredentialPatch) error {
	var sets []string
	var args []any
	i := 1
	next := func() string { n := fmt.Sprintf("$%d", i); i++; return n }
	if p.PasswordHash != nil {
		sets = append(sets, "password_hash="+next())
		args = append(args, *p.PasswordHash)
	}
	if p.MustChange != nil {
		sets = append(sets, "must_change="+next())
		args = append(args, *p.MustChange)
	}
	if p.Admin != nil {
		sets = append(sets, "admin="+next())
		args = append(args, *p.Admin)
	}
	if p.TOTPEnabled != nil {
		sets = append(sets, "totp_enabled="+next())
		args = append(args, *p.TOTPEnabled)
	}
	if p.TOTPSecret != nil {
		sets = append(sets, "totp_secret="+next())
		if len(*p.TOTPSecret) == 0 {
			args = append(args, nil)
		} else {
			args = append(args, *p.TOTPSecret)
		}
	}
	if p.TOTPLastStep != nil {
		sets = append(sets, "totp_last_step="+next())
		args = append(args, *p.TOTPLastStep)
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at="+next())
	args = append(args, ns(s.now()), userID)
	return s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx,
			`UPDATE credentials SET `+strings.Join(sets, ", ")+fmt.Sprintf(` WHERE user_id=$%d`, i), args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
}

func (s *Store) SetRecoveryCodes(ctx context.Context, userID string, hashes [][32]byte) error {
	return s.wtx(ctx, func(q qtx) error {
		if _, err := q.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id=$1`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := q.Exec(ctx,
				`INSERT INTO recovery_codes(user_id, code_hash) VALUES($1,$2)`, userID, h[:]); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID string, hash [32]byte) (int, error) {
	var remaining int
	err := s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx,
			`UPDATE recovery_codes SET used_at=$1 WHERE user_id=$2 AND code_hash=$3 AND used_at IS NULL`,
			ns(s.now()), userID, hash[:])
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return meta.ErrNotFound
		}
		return q.QueryRow(ctx,
			`SELECT COUNT(*) FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).
			Scan(&remaining)
	})
	return remaining, err
}

func (s *Store) AdvanceTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	var ok bool
	err := s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx,
			`UPDATE credentials SET totp_last_step=$1, updated_at=$2 WHERE user_id=$3 AND totp_last_step<$4`,
			step, ns(s.now()), userID, step)
		if err != nil {
			return err
		}
		ok = tag.RowsAffected() > 0
		return nil
	})
	return ok, err
}

const wsCols = `id_hash, user_id, kind, method, admin, csrf, created_at, last_seen_at, expires_at, ip, user_agent, attempts`

func (s *Store) CreateWebSession(ctx context.Context, ws meta.WebSession) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `INSERT INTO web_sessions(`+wsCols+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			ws.IDHash[:], ws.UserID, ws.Kind, ws.Method, ws.Admin, ws.CSRF[:],
			ns(ws.CreatedAt), ns(ws.LastSeenAt), ns(ws.ExpiresAt), ws.IP, ws.UserAgent, ws.Attempts)
		return err
	})
}

func scanWS(row pgx.Row) (meta.WebSession, error) {
	var w meta.WebSession
	var idh, csrf []byte
	var created, seen, exp int64
	err := row.Scan(&idh, &w.UserID, &w.Kind, &w.Method, &w.Admin, &csrf, &created, &seen, &exp,
		&w.IP, &w.UserAgent, &w.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, meta.ErrNotFound
	}
	if err != nil {
		return w, err
	}
	copy(w.IDHash[:], idh)
	copy(w.CSRF[:], csrf)
	w.CreatedAt = time.Unix(0, created).UTC()
	w.LastSeenAt = time.Unix(0, seen).UTC()
	w.ExpiresAt = time.Unix(0, exp).UTC()
	return w, nil
}

func (s *Store) GetWebSession(ctx context.Context, idHash [32]byte) (meta.WebSession, error) {
	return scanWS(s.pool.QueryRow(ctx,
		`SELECT `+wsCols+` FROM web_sessions WHERE id_hash=$1`, idHash[:]))
}

func (s *Store) TouchWebSession(ctx context.Context, idHash [32]byte, at time.Time) error {
	return s.wtx(ctx, func(q qtx) error {
		_, err := q.Exec(ctx, `UPDATE web_sessions SET last_seen_at=$1 WHERE id_hash=$2`, ns(at), idHash[:])
		return err
	})
}

func (s *Store) BumpWebSessionAttempts(ctx context.Context, idHash [32]byte) (int, error) {
	var n int
	err := s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx, `UPDATE web_sessions SET attempts=attempts+1 WHERE id_hash=$1`, idHash[:])
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return meta.ErrNotFound
		}
		return q.QueryRow(ctx, `SELECT attempts FROM web_sessions WHERE id_hash=$1`, idHash[:]).Scan(&n)
	})
	return n, err
}

func (s *Store) DeleteWebSession(ctx context.Context, idHash [32]byte) error {
	return s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx, `DELETE FROM web_sessions WHERE id_hash=$1`, idHash[:])
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string, except *[32]byte) (int, error) {
	var n int
	err := s.wtx(ctx, func(q qtx) error {
		var tag pgconn.CommandTag
		var err error
		if except != nil {
			tag, err = q.Exec(ctx, `DELETE FROM web_sessions WHERE user_id=$1 AND id_hash<>$2`, userID, except[:])
		} else {
			tag, err = q.Exec(ctx, `DELETE FROM web_sessions WHERE user_id=$1`, userID)
		}
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		return nil
	})
	return n, err
}

func (s *Store) ListWebSessions(ctx context.Context, userID string) ([]meta.WebSession, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+wsCols+` FROM web_sessions WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.WebSession
	for rows.Next() {
		var w meta.WebSession
		var idh, csrf []byte
		var created, seen, exp int64
		if err := rows.Scan(&idh, &w.UserID, &w.Kind, &w.Method, &w.Admin, &csrf, &created, &seen, &exp,
			&w.IP, &w.UserAgent, &w.Attempts); err != nil {
			return nil, err
		}
		copy(w.IDHash[:], idh)
		copy(w.CSRF[:], csrf)
		w.CreatedAt = time.Unix(0, created).UTC()
		w.LastSeenAt = time.Unix(0, seen).UTC()
		w.ExpiresAt = time.Unix(0, exp).UTC()
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) PurgeWebSessions(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.wtx(ctx, func(q qtx) error {
		tag, err := q.Exec(ctx, `DELETE FROM web_sessions WHERE expires_at<$1`, ns(now))
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		return nil
	})
	return n, err
}
