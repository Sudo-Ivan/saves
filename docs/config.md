# savesd configuration reference

Generated from internal/config struct tags by internal/config/gendoc. Do not edit.

Every duration accepts human strings like 30s, 5m, 24h, 90d, and every
size accepts strings like 512MiB or 10GB. Bare numbers mean seconds and bytes.

Environment overrides: SAVES_<SECTION>_<KEY> set any scalar, for example
SAVES_LISTEN_ADDR or SAVES_LOG_LEVEL. Secret fields accept a <name>_file
sibling that reads the value from a file, or the matching *_FILE environment
variable. Sections reloadable on SIGHUP: quota, limits, log, auth.

## listen

main HTTP listener

- listen.addr: listen address
### listen.tls

TLS mode and material

- listen.tls.mode: files, acme, or none
- listen.tls.cert_file: certificate chain PEM for mode files
- listen.tls.key_file (secret): private key PEM for mode files
- listen.tls.min_version: 1.2 or 1.3
- listen.tls.hot_reload: poll cert files for changes and reload without restart
#### listen.tls.acme

ACME client settings for mode acme

- listen.tls.acme.email: contact email for the ACME account
- listen.tls.acme.directory_url: ACME directory URL, empty means the autocert default
- listen.tls.acme.cache_dir: directory holding ACME account and certificate cache
- listen.tls.acme.hosts (list): allowed certificate host names
- listen.protocols (list): enabled protocols: h1, h2, h3, h2c
- listen.h3_addr: UDP listen address for HTTP/3, defaults to addr
- listen.alt_svc: Alt-Svc header value advertised on TCP responses
- listen.read_header_timeout: deadline for reading request headers
- listen.idle_timeout: keep alive idle timeout
- listen.shutdown_timeout: graceful drain deadline on SIGTERM
- listen.max_header_bytes: largest accepted request header block
- listen.max_conns: max simultaneous connections, 0 is unlimited
- listen.min_throughput: bytes per second floor that extends per request deadlines
- listen.udp_buffer_bytes: UDP socket buffer size for HTTP/3
### listen.h2

HTTP/2 settings

- listen.h2.max_concurrent_streams: max streams per connection
- listen.h2.max_read_frame_size: largest accepted frame payload
- listen.h2.idle_timeout: connection idle timeout
## ops

operational listener for health, metrics, pprof

- ops.enabled: serve the ops listener
- ops.addr: listen address, loopback recommended
- ops.pprof: expose /debug/pprof
## storage

blob and metadata backends

### storage.blob

content addressed blob store

- storage.blob.driver: fs or s3
#### storage.blob.fs

filesystem backend options

- storage.blob.fs.root: blob store root directory
- storage.blob.fs.fsync: fsync policy: always, dir, or never
#### storage.blob.s3

S3 backend options

- storage.blob.s3.endpoint: S3 endpoint host or URL, empty for AWS
- storage.blob.s3.region: bucket region
- storage.blob.s3.bucket: bucket name
- storage.blob.s3.prefix: key prefix prepended to all objects
- storage.blob.s3.access_key (secret): access key id
- storage.blob.s3.secret_key (secret): secret access key
- storage.blob.s3.secret_key_file: path to file containing the secret key
- storage.blob.s3.path_style: use path style addressing instead of virtual host
- storage.blob.s3.insecure: use plain HTTP instead of HTTPS
- storage.blob.s3.request_timeout: per request deadline
- storage.blob.s3.max_retries: retry attempts for transient failures
### storage.meta

metadata database

- storage.meta.driver: sqlite or postgres
#### storage.meta.sqlite

sqlite options

- storage.meta.sqlite.path: database file path
#### storage.meta.postgres

postgres options

- storage.meta.postgres.dsn (secret): connection string
- storage.meta.postgres.dsn_file: path to file containing the DSN
- storage.meta.postgres.max_conns: pool maximum connections
- storage.meta.postgres.min_conns: pool minimum connections
## auth

authentication method chain

- auth.order (list): method chain order: token, oidc, proxy, anonymous
### auth.token

opaque bearer token method

- auth.token.enabled: accept sv1_ bearer tokens
- auth.token.last_used_interval: minimum interval between last_used writes
- auth.token.cache_ttl: token validation cache lifetime; revocation propagates within this window
### auth.oidc

OIDC JWT bearer method

- auth.oidc.enabled: accept OIDC JWTs
- auth.oidc.issuer: expected issuer, used for JWKS discovery
- auth.oidc.audience: expected audience
- auth.oidc.algs (list): allowed algorithms: RS256, ES256, EdDSA
- auth.oidc.auto_provision: create a user for an unknown subject
- auth.oidc.scope_claim: claim carrying scopes
- auth.oidc.clock_skew: allowed exp and nbf clock skew
- auth.oidc.jwks_cache_ttl: JWKS cache lifetime
- auth.oidc.jwks_min_refresh: minimum interval between JWKS refreshes
### auth.proxy

trusted reverse proxy header method

- auth.proxy.enabled: accept identity headers from trusted proxies
- auth.proxy.header: header carrying the user subject
- auth.proxy.trusted_cidrs (list): CIDRs allowed to assert identity
### auth.anonymous

anonymous method keyed by client IP

- auth.anonymous.enabled: accept unauthenticated requests
- auth.anonymous.scopes (list): scopes granted to anonymous principals
- auth.ip_secret (secret): secret for anonymous identity hashing
- auth.ip_secret_file: path to file containing ip_secret
- auth.failed_auth_per_sec: failed auth rate limit per IP
## registration

self service user registration

- registration.mode: closed, invite, or open
- registration.invite_codes (list): valid invite codes
- registration.invite_codes_file: path to file with one invite code per line
- registration.invite_max_uses: max uses per invite code, 0 is unlimited
- registration.per_sec: registration rate limit per IP for mode open
## quota

tiers, defaults, and per app policy

- quota.default_tier: tier assigned to new users
- quota.anonymous_tier: tier for anonymous principals
- quota.allow_unknown_apps: regex for app ids allowed without a policy entry
- quota.tiers (map): quota tiers by name
- quota.apps (map): per app policy by app id
## limits

manifest, chunk, and request limits

- limits.inline_max_bytes: largest file stored inline in a manifest
- limits.min_chunk_bytes: smallest allowed non-final chunk
- limits.max_chunk_bytes: largest accepted chunk upload
- limits.max_files: max file entries per snapshot
- limits.max_chunks_per_snapshot: max total chunk refs per snapshot
- limits.max_file_bytes: global largest single file
- limits.max_snapshot_bytes: global largest summed file sizes
- limits.max_manifest_bytes: largest accepted manifest body
- limits.manifest_cache_bytes: decoded manifest cache size per process, 0 disables
- limits.require_encryption: require vault encrypted manifests for all snapshots
- limits.max_path_depth: deepest allowed path component count
- limits.max_concurrent_uploads: global parallel chunk upload cap
## gc

garbage collection schedule

- gc.interval: time between gc cycles
- gc.grace_period: minimum unreferenced age before deletion
- gc.pending_ttl: lifetime of an uncommitted pending snapshot
- gc.batch_size: max rows per gc batch
- gc.lease_holder: identity used for the gc leader lease
## sandbox

Landlock sandbox policy

- sandbox.mode: off, best-effort, or enforce
- sandbox.allow_root: permit running as uid 0
- sandbox.extra_ro_paths (list): additional read only paths
- sandbox.extra_rw_paths (list): additional read write paths
- sandbox.extra_connect_tcp_ports (list): additional outbound TCP ports
- sandbox.extra_bind_tcp_ports (list): additional bound TCP ports
## log

logging

- log.level: debug, info, warn, or error
- log.format: json or text
- log.access: emit an access log line per request
## cors

cross origin resource sharing, off by default

- cors.enabled: emit CORS headers
- cors.allowed_origins (list): allowed origin values
- cors.allowed_methods (list): allowed methods
- cors.allowed_headers (list): allowed headers
- cors.max_age: preflight cache lifetime
## metrics

Prometheus metrics

- metrics.enabled: expose metrics on the ops listener
- metrics.namespace: metric name prefix
