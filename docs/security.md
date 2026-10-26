# Security

## Threat model

savesd protects save data at rest in the blob and metadata stores and in
transit over TLS. The server is trusted with plaintext unless the client
vault is enabled. Admins with the admin scope can manage users and data.

## Authentication

Bearer sv1_ tokens with read, write or admin scopes, hashed at rest.
A token can never out-scope or out-range its creator (scopes must be a
subset of the caller's, apps within the caller's allowlist). Tokens may
restrict the client address with allowed_cidrs. The client IP is the
direct peer, resolved through proxy.trusted_cidrs and
proxy.real_ip_header when those are configured, so a spoofed
X-Forwarded-For from an untrusted peer cannot satisfy an allowlist. A
denied request returns the same 401 body as a bad token. Per-token
audit events record management actions and denied authentications
(denied events only when the secret was correct, rate limited one per
token per address per minute). Usage is aggregated hourly per address.
Both are retained for auth.token.audit_retention (default 90d) and never
contain secrets or raw URLs.
OIDC JWTs, trusted proxy headers and anonymous IP identity are
configurable. Registration is closed, invite or open.

## Web UI

The optional web UI stores only argon2id password hashes, sealed TOTP
secrets, hashed recovery codes, and SHA-256 session ids. Session and
CSRF cookies are HttpOnly. Every form carries a CSRF token plus Fetch
Metadata checks; responses send a strict CSP with no inline script or
style. Login failures are generic and rate limited per IP prefix and
per username. Audit log lines record ids, methods and IP prefixes only:
passwords, tokens, codes, cookie values and secrets are never logged.
See docs/web.md.

## Rate limiting

Per-IP and per-principal token buckets cover authentication failures,
requests and concurrent uploads; per-tier quotas cap storage and
snapshot counts.

## Sandbox

On Linux savesd optionally confines itself with Landlock. Enforced:

- filesystem read, write and execute restricted to config, data and
  listed extra paths,
- TCP bind only on the listen and ops ports, TCP connect only to
  listed services (postgres, S3, ACME, OIDC, DNS),
- UDP bind only on the HTTP/3 port when h3 is enabled,
- abstract unix sockets and signal scope isolation.

UDP sends are NOT restricted: a QUIC server replies to arbitrary
ephemeral client ports and Landlock ConnectSendUDP works per
destination port, which cannot be whitelisted in advance.

`savesd sandbox-check --json` reports the enforceable set per host:
abi (Landlock ABI version), fs, tcp, udp, scoped booleans.

## Hardening

deploy/systemd/savesd.service ships NoNewPrivileges, ProtectSystem,
PrivateTmp, restricted address families, syscall filters and an empty
capability set.

## Vault leakage

With the vault enabled the server sees only: app id, slot names,
snapshot timing, file count, ciphertext sizes, and intra-user chunk
equality. File names, sizes and contents are hidden.

## TLS

TLS 1.2 or 1.3, certificate files or ACME. P2P uses TLS 1.3 with device
public key pinning instead of a CA.

## Reporting

Report vulnerabilities through GitHub Security Advisories on the
repository.

## Container notes

The distroless image runs as a nonroot user with a read-only root
filesystem. Under the default podman and docker seccomp profile the
Landlock syscalls are allowed, so sandbox mode enforce works inside the
container; with a custom seccomp profile that filters landlock syscalls,
use best-effort or the container will refuse to start in enforce mode.

## Admin console

Admin pages require a web admin session. Destructive actions such as
password replacement and user deletion ask for the admin password again.
The IP blocklist is enforced at the front of every request, refuses to
cover the caller or trusted proxies, and audits blocks once per address
per ten minutes. The audit log records moderation, settings and login
events with ip and request id but never credentials. Bans disable the
account, revoke web sessions and optionally revoke API tokens; the token
cache is invalidated on revocation.

## Raw file route

The snapshot viewer raw route serves file bytes under a sandbox CSP with
nosniff and attachment disposition for everything except safe image
types.
