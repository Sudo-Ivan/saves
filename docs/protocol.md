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
quota_exceeded (413), rate_limited (429), bandwidth_exceeded (429, Retry-After set), conflict (409), encrypted
(409), encryption_required (400), too_large.

## Encryption

With the vault enabled the manifest carries only opaque path ids and
sealed chunks plus a sealed metadata entry; see docs/vault.md.

## Tokens

Create with POST /v1/tokens (admins can also use POST /v1/admin/users/{id}/tokens). The body takes name, scopes, apps, allowed_cidrs and an expiry given as either expires_at (RFC 3339) or expires_in (a duration such as 720h or 30d, at least one minute, at most ten years). Sending both is a 400. An invalid expiry is a 400 and creates nothing. Without an expiry the token never expires unless auth.token.max_ttl is set, in which case max_ttl is applied. A token can never carry scopes or apps beyond its creator's own.

allowed_cidrs is a list of up to 16 addresses or CIDRs. Requests from other client addresses get the same 401 as an invalid token.

Token objects carry id, user_id, name, scopes, apps, allowed_cidrs, created_at, expires_at, revoked_at and last_used_at. They never carry the secret or its hash. The secret is returned once, at creation.

GET /v1/tokens lists the caller's tokens. GET /v1/tokens/{id} returns one. PATCH /v1/tokens/{id} changes name, allowed_cidrs and the expiry (expires_at or expires_in, with expires_at null clearing it when max_ttl is unset). A revoked token cannot be edited. The owner or an admin may use these routes on a token.

GET /v1/tokens/{id}/events returns audit events newest first as items plus next_cursor. Query parameters are kind, limit (1 to 100, default 50) and cursor. Items carry id, at, kind, ip, actor_user_id, user_agent and detail. Kinds are created, revoked, renamed, expiry_changed, cidr_changed, first_use, new_ip, denied_ip, denied_expired and denied_revoked.

GET /v1/tokens/{id}/stats returns total_requests, requests_24h, requests_7d, requests_30d, daily_30d (30 counts, oldest first), unique_ips_30d, top_ips, denied_30d, first_use and last_use.

## Events

GET /v1/events streams text/event-stream head events per slot with ids,
keepalives and a lag event when the buffer drops entries.

## P2P transport

One device hosts an embedded node; peers reach it over QUIC http3 with
mutual TLS pinned to device identities. Everything else is the same API.
