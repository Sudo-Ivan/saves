CREATE TABLE IF NOT EXISTS credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL DEFAULT '',
  admin BOOLEAN NOT NULL DEFAULT FALSE,
  must_change BOOLEAN NOT NULL DEFAULT FALSE,
  totp_secret BYTEA,
  totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  totp_last_step BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  user_id TEXT NOT NULL REFERENCES users(id),
  code_hash BYTEA NOT NULL,
  used_at BIGINT,
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE IF NOT EXISTS web_sessions (
  id_hash BYTEA PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,
  method TEXT NOT NULL,
  admin BOOLEAN NOT NULL DEFAULT FALSE,
  csrf BYTEA NOT NULL,
  created_at BIGINT NOT NULL,
  last_seen_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS web_sessions_user ON web_sessions(user_id);
CREATE INDEX IF NOT EXISTS web_sessions_exp ON web_sessions(expires_at);
