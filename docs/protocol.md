# Protocol

See api/openapi.yaml for the full route list.

## Write path

Push happens in three phases.

1. POST /v1/apps/{app}/slots/{slot}/snapshots begins a pending snapshot
   and returns an id and the chunk hashes the server already has.
2. PUT .../snapshots/{id}/chunks/{hash} uploads each missing chunk.
3. POST .../snapshots/{id}/commit publishes the manifest atomically.
   If-Match on the slot ETag makes concurrent commits a conflict.

Pending snapshots expire without a commit.

## Read path

Pull fetches the manifest, downloads missing chunks by hash from
GET /v1/apps/{app}/chunks/{hash} (Range supported), then writes files.
Individual files and tar archives can also be read directly.

## Manifest

The manifest lists files (path, size, mode, mtime, chunk refs or inline
bytes) and directories, canonically serialized. Validation covers path
rules, counts, sizes and the chunk slack for sealed chunks.

## Chunking

Content-defined chunking (FastCDC) with configurable min, average and
max sizes. Small files travel inline inside the manifest.

## Path rules

Manifest paths are forward slash relative paths inside named roots.
Reserved device names and traversal are rejected.

## Errors

application/problem+json with a stable machine readable code member:
quota_exceeded (413), rate_limited (429), conflict (409), encrypted
(409), encryption_required (400), too_large.

## Encryption

With the vault enabled the manifest carries only opaque path ids and
sealed chunks plus a sealed metadata entry; see docs/vault.md.

## Events

GET /v1/events streams text/event-stream head events per slot with ids,
keepalives and a lag event when the buffer drops entries.

## P2P transport

One device hosts an embedded node; peers reach it over QUIC http3 with
mutual TLS pinned to device identities. Everything else is the same API.
