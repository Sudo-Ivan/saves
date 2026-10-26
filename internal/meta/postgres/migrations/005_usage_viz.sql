CREATE TABLE bandwidth_usage (
  user_id VARCHAR(200) NOT NULL,
  day BIGINT NOT NULL,
  up_bytes BIGINT NOT NULL DEFAULT 0,
  down_bytes BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);
