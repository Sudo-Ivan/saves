# SDKs

Client libraries for the saves HTTP API live under sdk/. Every SDK follows
the same contract so a launcher can switch languages without relearning the
protocol. The wire protocol is documented in api/openapi.yaml and
docs/protocol.md.

| Language | Directory | Dependencies |
|----------|-----------|--------------|
| Rust | sdk/rust | ureq, serde, serde_json, sha2 |
| C++17 | sdk/cpp | libcurl, vendored nlohmann/json and SHA-256 |
| C# | sdk/csharp | none beyond the .NET base library |
| TypeScript | sdk/typescript | none, uses fetch and Web Crypto |
| Python | sdk/python | none, standard library only |
| Java | sdk/java | none, JDK 11 java.net.http |

## What an SDK covers

Low level client, one method per route:

- identity: me, register
- apps: list apps, list slots, get slot, delete slot
- snapshots: list, get manifest, begin, put chunk, commit, delete, diff
- reading: get chunk (optional range), get file, download archive
- tokens: list, create, get, patch, revoke, events, stats
- vault header: get, put, delete
- events: server-sent events stream with reconnect

High level helpers built on the client:

- push(app, slot, directory, options) uploads a directory as a snapshot
- pull(app, slot, snapshot, directory) downloads a snapshot into a directory

The SDKs do not implement the client-side vault. A snapshot with an enc
marker in its manifest is reported as an Encrypted error and never written
to disk. Use the savesctl client for vault snapshots.

## Contract

Configuration: base URL, bearer token, optional user agent, request timeout
(default 30 seconds), retry count (default 3).

Authentication: every request carries Authorization: Bearer <token>. Tokens
look like sv1_<16 hex>_<43 base64url>. The SDK never logs the token.

Errors: failures raise or return one error type with the HTTP status, the
stable code from the application/problem+json body (unauthorized, forbidden,
not_found, conflict, encrypted, encryption_required, too_large,
quota_exceeded, rate_limited, bandwidth_exceeded, maintenance, ip_blocked,
bad_request, internal, pending_approval), the title, the detail, the request
id from X-Request-Id, and Retry-After seconds when present. A head conflict
(409 conflict on commit) also exposes the current head snapshot.

Retries: the SDK retries 429 and 503 after Retry-After (or exponential
backoff from 500 ms capped at 10 s with jitter), and retries network errors
and 5xx for idempotent requests only: GET, HEAD, DELETE and PUT chunk. POST
begin and commit are never retried automatically on a 5xx or a network
error, because the outcome is unknown. They are retried on 429 and 503 which
are returned before any state change.

### Push

1. Read limits once with GET /v1/me, field limits: inline_max_bytes,
   min_chunk_bytes, max_chunk_bytes, max_files, max_file_bytes,
   max_snapshot_bytes, max_path_depth.
2. Walk the directory. Paths are relative, slash separated, and prefixed with
   a root name (default save), for example save/world/level.dat. Reject paths
   that fail the server rules: no empty segments, no dot or dot-dot segments,
   no backslashes, no control characters, no reserved device names, at most
   max_path_depth segments. Skip symlinks. Sort files by path, bytewise.
3. A file of at most inline_max_bytes goes inline: the manifest entry carries
   inline as base64 and no chunks.
4. Larger files are split into fixed size chunks of chunk_size bytes, default
   1 MiB, clamped between min_chunk_bytes and max_chunk_bytes. Every chunk
   except the last of a file must be at least min_chunk_bytes. Each chunk
   reference is {"h": sha256 lowercase hex, "n": byte length}.
5. Manifest JSON: {"version":1,"device":...,"label":...,"files":[{"path",
   "size","mode","mtime_ns","chunks":[{"h","n"}]|"inline":base64}],"dirs":[
   explicit empty directories]}. mode is permission bits masked to 0777.
   mtime_ns is Unix nanoseconds. Optional "parent" is the previous head id.
6. POST /v1/apps/{app}/slots/{slot}/snapshots with the manifest returns
   {"id","missing":[hashes],"expires_at","chunk_url"}.
7. PUT /v1/apps/{app}/slots/{slot}/snapshots/{id}/chunks/{hash} for every
   hash in missing, body is the raw chunk bytes, Content-Length is required,
   up to 4 uploads in parallel. A 201 means stored. Re-sending a stored chunk
   is safe.
8. POST /v1/apps/{app}/slots/{slot}/snapshots/{id}/commit. Send If-Match with
   the id of the head the push was based on (the slot head from GET
   /v1/apps/{app}/slots/{slot}, field head_snapshot_id) to get a conflict
   instead of overwriting. Add ?force=1 only when the caller asks for it.
   Returns the committed snapshot.
9. Progress callback receives bytes uploaded and bytes total.

### Pull

1. GET /v1/apps/{app}/slots/{slot}/snapshots/{id}, send Accept-Encoding gzip,
   decode the manifest. Callers pass a snapshot id, listing snapshots first when
   they want the newest.
2. Refuse an encrypted manifest (enc present).
3. For every file: reject unsafe paths (absolute, traversal, backslashes),
   create parent directories, write inline bytes or fetch each chunk with GET
   /v1/apps/{app}/chunks/{hash}, verify the SHA-256 of every chunk against its
   reference and the total size against the entry, write to a temporary file in
   the destination directory and rename into place, set mode and mtime.
4. Create explicit directories. Never delete files that are not in the
   snapshot unless the caller sets the prune option.

### Events

GET /v1/events with Accept: text/event-stream. Parse id, event and data
fields, expose each event with its name and JSON data, reconnect with
backoff and Last-Event-ID, stop when the caller cancels.

## Testing

Each SDK ships unit tests that run offline against a mock HTTP server, and an
integration test that runs against a real savesd. The shared harness in
sdk/test.sh builds savesd, runs savesd init in a temporary directory with the
sandbox off, starts it on a free port, exports SAVES_URL and SAVES_TOKEN, and
runs every SDK integration test that has its toolchain installed. The
integration test pushes a directory with an inline file, a multi-chunk file
and an empty directory, pulls it into a second directory and compares every
byte, checks a head conflict on a stale If-Match, lists and deletes the
snapshot, and creates, patches and revokes a token.
