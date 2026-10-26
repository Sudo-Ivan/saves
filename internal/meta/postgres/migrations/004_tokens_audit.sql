ALTER TABLE tokens ADD COLUMN allowed_cidrs TEXT NOT NULL DEFAULT '';

CREATE TABLE token_events (
  id VARCHAR(200) PRIMARY KEY,
  token_id VARCHAR(200) NOT NULL,
  user_id VARCHAR(200) NOT NULL,
  at BIGINT NOT NULL,
  kind VARCHAR(200) NOT NULL,
  ip VARCHAR(200) NOT NULL DEFAULT '',
  actor_user_id VARCHAR(200) NOT NULL DEFAULT '',
  user_agent VARCHAR(200) NOT NULL DEFAULT '',
  request_id VARCHAR(200) NOT NULL DEFAULT '',
  detail VARCHAR(200) NOT NULL DEFAULT ''
);
CREATE INDEX token_events_token_at ON token_events (token_id, at DESC);
CREATE INDEX token_events_at ON token_events (at);

CREATE TABLE token_usage (
  token_id VARCHAR(200) NOT NULL,
  bucket BIGINT NOT NULL,
  ip VARCHAR(200) NOT NULL,
  requests BIGINT NOT NULL,
  last_seen BIGINT NOT NULL,
  user_agent VARCHAR(200) NOT NULL DEFAULT '',
  PRIMARY KEY (token_id, bucket, ip)
);
CREATE INDEX token_usage_token_bucket ON token_usage (token_id, bucket);
CREATE INDEX token_usage_bucket ON token_usage (bucket);
