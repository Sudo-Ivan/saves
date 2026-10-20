CREATE TABLE users (
  id TEXT PRIMARY KEY,
  subject TEXT NOT NULL UNIQUE,
  tier TEXT NOT NULL,
  quota_bytes INTEGER,
  disabled INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  secret_hash BLOB NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  scopes TEXT NOT NULL DEFAULT '',
  apps TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER,
  last_used_at INTEGER
);

CREATE TABLE usage (
  user_id TEXT PRIMARY KEY,
  used_bytes INTEGER NOT NULL DEFAULT 0,
  reserved_bytes INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE slots (
  user_id TEXT NOT NULL,
  app TEXT NOT NULL,
  name TEXT NOT NULL,
  head_snapshot_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, app, name)
);

CREATE TABLE snapshots (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  app TEXT NOT NULL,
  slot TEXT NOT NULL,
  parent_id TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  manifest_hash BLOB NOT NULL,
  manifest_size INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  file_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  committed_at INTEGER,
  expires_at INTEGER
);
CREATE INDEX idx_snapshots_slot ON snapshots(user_id, app, slot, created_at DESC);
CREATE INDEX idx_snapshots_pending ON snapshots(user_id, state, expires_at);

CREATE TABLE snapshot_chunks (
  snapshot_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  hash BLOB NOT NULL,
  PRIMARY KEY (snapshot_id, hash)
);
CREATE INDEX idx_snap_chunks_user ON snapshot_chunks(user_id, hash);

CREATE TABLE chunks (
  user_id TEXT NOT NULL,
  hash BLOB NOT NULL,
  size INTEGER NOT NULL,
  state TEXT NOT NULL,
  refcount INTEGER NOT NULL DEFAULT 0,
  zero_ref_since INTEGER,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, hash)
);
CREATE INDEX idx_chunks_unref ON chunks(user_id, refcount, zero_ref_since);

CREATE TABLE manifests (
  user_id TEXT NOT NULL,
  hash BLOB NOT NULL,
  size INTEGER NOT NULL,
  refcount INTEGER NOT NULL DEFAULT 0,
  zero_ref_since INTEGER,
  PRIMARY KEY (user_id, hash)
);

CREATE TABLE leases (
  name TEXT PRIMARY KEY,
  holder TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
