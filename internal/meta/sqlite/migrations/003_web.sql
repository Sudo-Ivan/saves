CREATE TABLE credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL DEFAULT '',
  admin INTEGER NOT NULL DEFAULT 0,
  must_change INTEGER NOT NULL DEFAULT 0,
  totp_secret BLOB,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
  user_id TEXT NOT NULL REFERENCES users(id),
  code_hash BLOB NOT NULL,
  used_at INTEGER,
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE web_sessions (
  id_hash BLOB PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,
  method TEXT NOT NULL,
  admin INTEGER NOT NULL DEFAULT 0,
  csrf BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX web_sessions_user ON web_sessions(user_id);
CREATE INDEX web_sessions_exp ON web_sessions(expires_at);
