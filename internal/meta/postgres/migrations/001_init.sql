CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  subject TEXT NOT NULL UNIQUE,
  tier TEXT NOT NULL,
  quota_bytes BIGINT,
  disabled BOOLEAN NOT NULL DEFAULT FALSE,
  deleted_at BIGINT,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  secret_hash BYTEA NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  scopes TEXT NOT NULL DEFAULT '',
  apps TEXT NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL,
  expires_at BIGINT,
  revoked_at BIGINT,
  last_used_at BIGINT
);

CREATE TABLE IF NOT EXISTS usage (
  user_id TEXT PRIMARY KEY,
  used_bytes BIGINT NOT NULL DEFAULT 0,
  reserved_bytes BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS slots (
  user_id TEXT NOT NULL,
  app TEXT NOT NULL,
  name TEXT NOT NULL,
  head_snapshot_id TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, app, name)
);

CREATE TABLE IF NOT EXISTS snapshots (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  app TEXT NOT NULL,
  slot TEXT NOT NULL,
  parent_id TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  manifest_hash BYTEA NOT NULL,
  manifest_size BIGINT NOT NULL,
  total_bytes BIGINT NOT NULL,
  file_count BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  committed_at BIGINT,
  expires_at BIGINT
);
CREATE INDEX IF NOT EXISTS idx_snapshots_slot ON snapshots(user_id, app, slot, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshots_pending ON snapshots(user_id, state, expires_at);

CREATE TABLE IF NOT EXISTS snapshot_chunks (
  snapshot_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  hash BYTEA NOT NULL,
  PRIMARY KEY (snapshot_id, hash)
);
CREATE INDEX IF NOT EXISTS idx_snap_chunks_user ON snapshot_chunks(user_id, hash);

CREATE TABLE IF NOT EXISTS chunks (
  user_id TEXT NOT NULL,
  hash BYTEA NOT NULL,
  size BIGINT NOT NULL,
  state TEXT NOT NULL,
  refcount BIGINT NOT NULL DEFAULT 0,
  zero_ref_since BIGINT,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, hash)
);
CREATE INDEX IF NOT EXISTS idx_chunks_unref ON chunks(user_id, refcount, zero_ref_since);

CREATE TABLE IF NOT EXISTS manifests (
  user_id TEXT NOT NULL,
  hash BYTEA NOT NULL,
  size BIGINT NOT NULL,
  refcount BIGINT NOT NULL DEFAULT 0,
  zero_ref_since BIGINT,
  PRIMARY KEY (user_id, hash)
);

CREATE TABLE IF NOT EXISTS leases (
  name TEXT PRIMARY KEY,
  holder TEXT NOT NULL,
  expires_at BIGINT NOT NULL
);
