CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE invites (
  id TEXT PRIMARY KEY,
  code_hash BLOB NOT NULL UNIQUE,
  code_prefix TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  max_uses INTEGER NOT NULL DEFAULT 0,
  uses INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE invite_uses (
  invite_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT ''
);

CREATE TABLE user_status (
  user_id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  at INTEGER NOT NULL,
  by TEXT NOT NULL DEFAULT '',
  until INTEGER
);

CREATE TABLE ip_blocks (
  id TEXT PRIMARY KEY,
  cidr TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  at INTEGER NOT NULL,
  actor_user_id TEXT NOT NULL DEFAULT '',
  actor_label TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT '',
  target_id TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_at ON audit_events (at DESC);
CREATE INDEX audit_target ON audit_events (target_id, at DESC);
CREATE INDEX audit_action ON audit_events (action, at DESC);

CREATE TABLE stats_daily (
  day INTEGER PRIMARY KEY,
  signups INTEGER NOT NULL DEFAULT 0,
  logins_ok INTEGER NOT NULL DEFAULT 0,
  logins_failed INTEGER NOT NULL DEFAULT 0,
  requests INTEGER NOT NULL DEFAULT 0,
  errors_5xx INTEGER NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  snapshots INTEGER NOT NULL DEFAULT 0,
  active_users INTEGER NOT NULL DEFAULT 0,
  storage_bytes INTEGER NOT NULL DEFAULT 0,
  users_total INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE user_activity (
  user_id TEXT NOT NULL,
  day INTEGER NOT NULL,
  PRIMARY KEY (user_id, day)
);
