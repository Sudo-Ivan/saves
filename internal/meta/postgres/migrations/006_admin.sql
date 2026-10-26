CREATE TABLE settings (
  key VARCHAR(280) PRIMARY KEY,
  value VARCHAR(280) NOT NULL,
  updated_at BIGINT NOT NULL,
  updated_by VARCHAR(280) NOT NULL DEFAULT ''
);

CREATE TABLE invites (
  id VARCHAR(280) PRIMARY KEY,
  code_hash BYTEA NOT NULL UNIQUE,
  code_prefix VARCHAR(280) NOT NULL DEFAULT '',
  label VARCHAR(280) NOT NULL DEFAULT '',
  max_uses BIGINT NOT NULL DEFAULT 0,
  uses BIGINT NOT NULL DEFAULT 0,
  expires_at BIGINT,
  created_by VARCHAR(280) NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL,
  revoked_at BIGINT
);

CREATE TABLE invite_uses (
  invite_id VARCHAR(280) NOT NULL,
  user_id VARCHAR(280) NOT NULL,
  at BIGINT NOT NULL,
  ip VARCHAR(280) NOT NULL DEFAULT ''
);

CREATE TABLE user_status (
  user_id VARCHAR(280) PRIMARY KEY,
  state VARCHAR(280) NOT NULL,
  reason VARCHAR(280) NOT NULL DEFAULT '',
  at BIGINT NOT NULL,
  by VARCHAR(280) NOT NULL DEFAULT '',
  until BIGINT
);

CREATE TABLE ip_blocks (
  id VARCHAR(280) PRIMARY KEY,
  cidr VARCHAR(280) NOT NULL,
  reason VARCHAR(280) NOT NULL DEFAULT '',
  created_by VARCHAR(280) NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL,
  expires_at BIGINT
);

CREATE TABLE audit_events (
  id VARCHAR(280) PRIMARY KEY,
  at BIGINT NOT NULL,
  actor_user_id VARCHAR(280) NOT NULL DEFAULT '',
  actor_label VARCHAR(280) NOT NULL DEFAULT '',
  action VARCHAR(280) NOT NULL,
  target_type VARCHAR(280) NOT NULL DEFAULT '',
  target_id VARCHAR(280) NOT NULL DEFAULT '',
  ip VARCHAR(280) NOT NULL DEFAULT '',
  detail VARCHAR(280) NOT NULL DEFAULT '',
  request_id VARCHAR(280) NOT NULL DEFAULT ''
);
CREATE INDEX audit_at ON audit_events (at DESC);
CREATE INDEX audit_target ON audit_events (target_id, at DESC);
CREATE INDEX audit_action ON audit_events (action, at DESC);

CREATE TABLE stats_daily (
  day BIGINT PRIMARY KEY,
  signups BIGINT NOT NULL DEFAULT 0,
  logins_ok BIGINT NOT NULL DEFAULT 0,
  logins_failed BIGINT NOT NULL DEFAULT 0,
  requests BIGINT NOT NULL DEFAULT 0,
  errors_5xx BIGINT NOT NULL DEFAULT 0,
  bytes_in BIGINT NOT NULL DEFAULT 0,
  bytes_out BIGINT NOT NULL DEFAULT 0,
  snapshots BIGINT NOT NULL DEFAULT 0,
  active_users BIGINT NOT NULL DEFAULT 0,
  storage_bytes BIGINT NOT NULL DEFAULT 0,
  users_total BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE user_activity (
  user_id VARCHAR(280) NOT NULL,
  day BIGINT NOT NULL,
  PRIMARY KEY (user_id, day)
);
