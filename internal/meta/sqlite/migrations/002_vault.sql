CREATE TABLE IF NOT EXISTS vault (
  user_id TEXT PRIMARY KEY,
  header BLOB NOT NULL CHECK(length(header) <= 8192),
  kid TEXT NOT NULL,
  version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
