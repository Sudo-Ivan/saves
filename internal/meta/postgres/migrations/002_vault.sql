CREATE TABLE IF NOT EXISTS vault (
  user_id TEXT PRIMARY KEY,
  header BYTEA NOT NULL CHECK(octet_length(header) <= 8192),
  kid TEXT NOT NULL,
  version BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
