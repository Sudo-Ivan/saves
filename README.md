# saves

Cross-platform game save synchronization. savesd is the server, savesctl
is the client CLI and daemon. Saves move as content-addressed chunks so
a small edit transfers only the changed data.

## Features

- Chunked delta sync with resumable uploads and range downloads.
- Per-user quotas and configurable tiers.
- Bearer token, OIDC, anonymous and invite registration auth.
- Optional client-side encryption: the server stores ciphertext only.
- HTTP/1, HTTP/2 and HTTP/3, ETag and If-Match concurrency, SSE events.
- Landlock filesystem sandbox for the server on Linux.
- Game and Minecraft world detection, including Wine and Proton roots.
- savesctl daemon for automatic sync and a system tray companion.
- Peer hosting: one device embeds a saves node and other devices sync to
  it over pinned-identity QUIC.

## Install

    go install github.com/Sudo-Ivan/saves/cmd/savesd@latest
    go install github.com/Sudo-Ivan/saves/cmd/savesctl@latest

Container and compose examples are in deploy/.

## Quick start

Server:

    savesd init -config saves.json
    savesd serve -config saves.json

Client:

    savesctl setup --server https://localhost:8443 --token <token>
    savesctl track auto
    savesctl sync
    savesctl daemon start

## Docs

docs/protocol.md, docs/cli.md, docs/vault.md, docs/security.md,
docs/deployment.md, docs/operations.md, docs/tray.md, api/openapi.yaml.

## Status

- P2P rendezvous, LAN discovery and NAT traversal are not implemented;
  the host device must be reachable directly.
- Windows binaries are cross-compiled and smoke tested under wine only.
- The Ludusavi manifest is downloaded on demand and not bundled; it is
  MIT licensed and fetched from the upstream repository.

License: 0BSD.
