# Operations

## init

`savesd init -config config.json` creates the first admin token and
prints it once. Store it in a secrets file; it grants the admin scope.

## admin

`savesd admin` manages users and tokens against the metadata store:

- `savesd admin user list|show|patch|delete`
- `savesd admin token create|list|revoke`
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
