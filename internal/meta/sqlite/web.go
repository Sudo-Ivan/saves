// SPDX-License-Identifier: 0BSD

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

const credCols = `user_id, username, password_hash, admin, must_change, totp_secret, totp_enabled, totp_last_step, created_at, updated_at` // #nosec G101 -- column list or usage text, not a credential

func scanCred(row *sql.Row) (meta.WebCredential, error) {
	var c meta.WebCredential
	var admin, must, totpOn, lastStep int64
	var secret []byte
	var created, updated int64
	err := row.Scan(&c.UserID, &c.Username, &c.PasswordHash, &admin, &must,
		&secret, &totpOn, &lastStep, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return c, meta.ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.Admin = admin != 0
	c.MustChange = must != 0
	c.TOTPSecret = secret
	c.TOTPEnabled = totpOn != 0
	c.TOTPLastStep = lastStep
	c.CreatedAt = time.Unix(0, created).UTC()
	c.UpdatedAt = time.Unix(0, updated).UTC()
	return c, nil
}

func (s *Store) GetCredentialByUsername(ctx context.Context, username string) (meta.WebCredential, error) {
	return scanCred(s.r.QueryRowContext(ctx,
		`SELECT `+credCols+` FROM credentials WHERE username=?`, strings.ToLower(username)))
}

func (s *Store) GetCredential(ctx context.Context, userID string) (meta.WebCredential, error) {
	return scanCred(s.r.QueryRowContext(ctx,
		`SELECT `+credCols+` FROM credentials WHERE user_id=?`, userID))
}

func (s *Store) CreateCredential(ctx context.Context, c meta.WebCredential) error {
	now := s.now()
	c.CreatedAt = now
	c.UpdatedAt = now
	_, err := s.w.ExecContext(ctx, `INSERT INTO credentials(`+credCols+`) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		c.UserID, strings.ToLower(c.Username), c.PasswordHash, b2i(c.Admin), b2i(c.MustChange),
		c.TOTPSecret, b2i(c.TOTPEnabled), c.TOTPLastStep, ns(now), ns(now))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return meta.ErrExists
	}
	return err
}

func (s *Store) UpdateCredential(ctx context.Context, userID string, p meta.CredentialPatch) error {
	var sets []string
	var args []any
	if p.PasswordHash != nil {
		sets = append(sets, "password_hash=?")
		args = append(args, *p.PasswordHash)
	}
	if p.MustChange != nil {
		sets = append(sets, "must_change=?")
		args = append(args, b2i(*p.MustChange))
	}
	if p.Admin != nil {
		sets = append(sets, "admin=?")
		args = append(args, b2i(*p.Admin))
	}
	if p.TOTPEnabled != nil {
		sets = append(sets, "totp_enabled=?")
		args = append(args, b2i(*p.TOTPEnabled))
	}
	if p.TOTPSecret != nil {
		sets = append(sets, "totp_secret=?")
		if len(*p.TOTPSecret) == 0 {
			args = append(args, nil)
		} else {
			args = append(args, *p.TOTPSecret)
		}
	}
	if p.TOTPLastStep != nil {
		sets = append(sets, "totp_last_step=?")
		args = append(args, *p.TOTPLastStep)
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at=?")
	args = append(args, ns(s.now()), userID)
	res, err := s.w.ExecContext(ctx,
		`UPDATE credentials SET `+strings.Join(sets, ", ")+` WHERE user_id=?`, args...) // #nosec G202 -- column names are fixed in code, values are bound
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return meta.ErrNotFound
	}
	return nil
}

func (s *Store) SetRecoveryCodes(ctx context.Context, userID string, hashes [][32]byte) error {
	return s.wtx(ctx, func(q q) error {
		if _, err := q.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := q.ExecContext(ctx,
				`INSERT INTO recovery_codes(user_id, code_hash) VALUES(?,?)`, userID, h[:]); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID string, hash [32]byte) (int, error) {
	var remaining int
	err := s.wtx(ctx, func(q q) error {
		res, err := q.ExecContext(ctx,
			`UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`,
			ns(s.now()), userID, hash[:])
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return meta.ErrNotFound
		}
		return q.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, userID).
			Scan(&remaining)
	})
	return remaining, err
}

func (s *Store) AdvanceTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	res, err := s.w.ExecContext(ctx,
		`UPDATE credentials SET totp_last_step=?, updated_at=? WHERE user_id=? AND totp_last_step<?`,
		step, ns(s.now()), userID, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

const wsCols = `id_hash, user_id, kind, method, admin, csrf, created_at, last_seen_at, expires_at, ip, user_agent, attempts`

func (s *Store) CreateWebSession(ctx context.Context, ws meta.WebSession) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO web_sessions(`+wsCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		ws.IDHash[:], ws.UserID, ws.Kind, ws.Method, b2i(ws.Admin), ws.CSRF[:],
		ns(ws.CreatedAt), ns(ws.LastSeenAt), ns(ws.ExpiresAt), ws.IP, ws.UserAgent, ws.Attempts)
	return err
}

func scanWS(scan func(...any) error) (meta.WebSession, error) {
	var w meta.WebSession
	var idh, csrf []byte
	var admin, attempts int64
	var created, seen, exp int64
	err := scan(&idh, &w.UserID, &w.Kind, &w.Method, &admin, &csrf, &created, &seen, &exp,
		&w.IP, &w.UserAgent, &attempts)
	if err != nil {
		return w, err
	}
	copy(w.IDHash[:], idh)
	copy(w.CSRF[:], csrf)
	w.Admin = admin != 0
	w.CreatedAt = time.Unix(0, created).UTC()
	w.LastSeenAt = time.Unix(0, seen).UTC()
	w.ExpiresAt = time.Unix(0, exp).UTC()
	w.Attempts = int(attempts)
	return w, nil
}

func (s *Store) GetWebSession(ctx context.Context, idHash [32]byte) (meta.WebSession, error) {
	w, err := scanWS(s.r.QueryRowContext(ctx,
		`SELECT `+wsCols+` FROM web_sessions WHERE id_hash=?`, idHash[:]).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return w, meta.ErrNotFound
	}
	return w, err
}

func (s *Store) TouchWebSession(ctx context.Context, idHash [32]byte, at time.Time) error {
	_, err := s.w.ExecContext(ctx, `UPDATE web_sessions SET last_seen_at=? WHERE id_hash=?`, ns(at), idHash[:])
	return err
}

func (s *Store) BumpWebSessionAttempts(ctx context.Context, idHash [32]byte) (int, error) {
	var n int
	err := s.wtx(ctx, func(q q) error {
		res, err := q.ExecContext(ctx, `UPDATE web_sessions SET attempts=attempts+1 WHERE id_hash=?`, idHash[:])
		if err != nil {
			return err
		}
		if r, _ := res.RowsAffected(); r == 0 {
			return meta.ErrNotFound
		}
		return q.QueryRowContext(ctx, `SELECT attempts FROM web_sessions WHERE id_hash=?`, idHash[:]).Scan(&n)
	})
	return n, err
}

func (s *Store) DeleteWebSession(ctx context.Context, idHash [32]byte) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM web_sessions WHERE id_hash=?`, idHash[:])
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return meta.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string, except *[32]byte) (int, error) {
	var res sql.Result
	var err error
	if except != nil {
		res, err = s.w.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id=? AND id_hash<>?`, userID, except[:])
	} else {
		res, err = s.w.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id=?`, userID)
	}
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *Store) ListWebSessions(ctx context.Context, userID string) ([]meta.WebSession, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT `+wsCols+` FROM web_sessions WHERE user_id=? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []meta.WebSession
	for rows.Next() {
		w, err := scanWS(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) PurgeWebSessions(ctx context.Context, now time.Time) (int, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at<?`, ns(now))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
