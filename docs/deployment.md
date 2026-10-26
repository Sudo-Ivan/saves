# Deployment guide

Three reference deployments live in deploy/.

## Small

deploy/config/small.json with deploy/compose-small.yaml: one savesd,
sqlite, fs blob store, no TLS (put it behind a reverse proxy). Suitable
for personal use up to a few devices.

## Public

deploy/config/public.json: TLS files, h2 and h3 on :443 with Alt-Svc,
invite registration. Set registration.require_encryption when only vault
clients should push.

## HA

deploy/config/ha.json with deploy/compose-ha.yaml: 3 savesd replicas,
postgres metadata, minio object store, nginx load balancer.

Notes:

- Run `savesd migrate` once before starting replicas (compose does this
  via the migrate service).
- GC uses the leader lease so only one replica collects at a time.
- h3 over UDP needs session consistency at the LB: pin by source IP or
  NAT UDP to a consistent backend. nginx can only do TCP LB without the
  stream module; use stream{} with hash $remote_addr consistent for UDP.
- Secrets are injected with *_file fields; mount them read only.

## Web UI

Enable the browser UI with SAVES_WEB_ENABLED=true and a secret via
SAVES_WEB_SECRET_FILE, and see docs/web.md for configuration, OIDC
setup, and reverse proxy snippets (nginx, Caddy, Traefik). When fronted
by a proxy set proxy.trusted_cidrs and web.public_url so forwarded
proto/host headers are honored safely.

## Sizing

A single small host handles tens of devices. HA sizing is bounded by
postgres for metadata traffic and by object storage bandwidth for
chunks.

## Backups

- sqlite: `savesd admin backup-meta` writes a consistent copy.
- postgres: `pg_dump` on a schedule.
- blobs: filesystem rsync or S3 bucket replication.
- Restore order: metadata first, then blobs.

## Upgrades

savesd runs migrations at startup when meta.auto_migrate is enabled, or
run `savesd migrate` before rolling the replicas.

## Monitoring

Metrics are on the ops listener (default 127.0.0.1:9090). Example alert
rules are in deploy/prometheus/alerts.yaml.

## Maintenance

Schedule `savesd admin gc` externally only if the built-in GC is
disabled; run `savesd admin fsck` after restores or crashes.
