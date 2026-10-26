# Operations

## init

`savesd init -config config.json` creates the first admin token and
prints it once. Store it in a secrets file; it grants the admin scope.

## admin

`savesd admin` manages users and tokens against the metadata store:

- `savesd admin user list|show|patch|delete`
- `savesd admin token create [-name N] [-scopes a,b] [-app a,b] [-expires 30d|720h|RFC3339|none] [-cidr 10.0.0.0/8,1.2.3.4]`
- `savesd admin token list <subject>`
- `savesd admin token show <id>` prints token fields and usage stats
- `savesd admin token events <id> [-kind K] [-n 50]` lists audit events
- `savesd admin token set <id> [-name N] [-expires V|none] [-cidr L|none]`
- `savesd admin token revoke <id>`
- `savesd admin backup-meta` writes a consistent copy of the sqlite
  metadata database to a path.
- `savesd admin stats` prints usage totals.

## migrate

`savesd migrate -config config.json` applies pending schema migrations.
Run it before starting replicas in HA deployments.

## fsck

`savesd fsck -config config.json` verifies metadata against the blob
store: manifests that reference missing chunks, orphaned blobs, and
corrupt entries are reported. Run after restores or crashes.

## gc

`savesd gc -config config.json` runs one garbage collection pass
immediately. The built-in GC loop (gc.interval in config) normally
handles this; use the command for manual reclaim after bulk deletes.

## backups

- sqlite: `savesd admin backup-meta`.
- postgres: `pg_dump`.
- blobs: rsync the fs root or replicate the S3 bucket.

## bandwidth limits

Bandwidth accounting and limits are off by default. Enable with
bandwidth.enabled, then set per-tier policies: upload_bytes_per_sec,
download_bytes_per_sec (rate throttles), daily_bytes and monthly_bytes
(period caps, UTC day and UTC calendar month, counting upload plus
download together). Server wide rate caps live under
bandwidth.global_upload_bytes_per_sec and
bandwidth.global_download_bytes_per_sec. A tier with no bandwidth
policy is unlimited but still counted.

Requests that hit a period cap get 429 with code bandwidth_exceeded and
a Retry-After to the next reset. In-flight transfers may overshoot a
cap by their own size. Per-user period totals converge across server
instances every 30 seconds, so caps are soft across nodes.

Metrics: saves_bandwidth_bytes_total{direction},
saves_bandwidth_throttle_seconds_total,
saves_bandwidth_rejections_total. Daily usage rows are kept for
bandwidth.retention (default 400 days).
