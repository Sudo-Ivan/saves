CREATE TABLE bandwidth_usage (
  user_id TEXT NOT NULL,
  day INTEGER NOT NULL,
  up_bytes INTEGER NOT NULL DEFAULT 0,
  down_bytes INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);
