ALTER TABLE tokens ADD COLUMN allowed_cidrs TEXT NOT NULL DEFAULT '';

CREATE TABLE token_events (
  id TEXT PRIMARY KEY,
  token_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  actor_user_id TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX token_events_token_at ON token_events (token_id, at DESC);
CREATE INDEX token_events_at ON token_events (at);

CREATE TABLE token_usage (
  token_id TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  ip TEXT NOT NULL,
  requests INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  user_agent TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (token_id, bucket, ip)
);
CREATE INDEX token_usage_token_bucket ON token_usage (token_id, bucket);
CREATE INDEX token_usage_bucket ON token_usage (bucket);
