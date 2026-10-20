# Security

## Threat model

savesd protects save data at rest in the blob and metadata stores and in
transit over TLS. The server is trusted with plaintext unless the client
vault is enabled. Admins with the admin scope can manage users and data.

## Authentication

Bearer sv1_ tokens with read, write or admin scopes, hashed at rest.
OIDC JWTs, trusted proxy headers and anonymous IP identity are
configurable. Registration is closed, invite or open.

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
