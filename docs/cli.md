# savesctl

Global flags: `--config PATH`, `--json`, `-v`.

## Setup

    savesctl setup --server URL --token T [--device-name N]
    savesctl login [--token T | --register] [--server URL]
    savesctl logout
    savesctl me
    savesctl doctor

## Tracking

    savesctl track add --path DIR --app A --slot S --key K
    savesctl track list | rm | auto | enable | disable
    savesctl games list | detect [--all]

A bare app id selects all tracked slots for that app.

## Sync

    savesctl sync [game...]
    savesctl push [game...] [--label L] [--force]
    savesctl pull [game...] [--snapshot ID]
    savesctl restore <game> [--snapshot ID] [--to DIR]
    savesctl snapshots <game>
    savesctl backups list | restore | prune
    savesctl status [game...]
    savesctl diff <game>
    savesctl delete-slot <app> <slot>
    savesctl delete-snapshot <game> <id>

## Vault

    savesctl vault init | unlock | lock | status | verify | disable
    savesctl vault change-passphrase
    savesctl vault recovery new

See docs/vault.md.

## Daemon

    savesctl daemon run | start | stop | status [--json] | logs [--json]
    savesctl daemon pause [game] | resume [game]
    savesctl daemon sync | conflicts | resolve <game> keep-local|keep-remote|keep-newest
    savesctl daemon install | uninstall | autostart-status

The daemon watches tracked games, syncs on change and on server events,
and reports conflicts for user resolution.

## Tray

    savesctl tray [--no-start-daemon]
    savesctl tray install | uninstall

See docs/tray.md.

## Peer to peer

    savesctl p2p id
    savesctl p2p host start [--listen ADDR] [--dir DIR] [--pair]
    savesctl p2p join <code>@<host:port>
    savesctl p2p peers [--json]
    savesctl p2p unpair <id>

One device hosts an embedded node and others join with a single use
pairing code; sync then works like a normal server, including the
daemon, tray and vault.

## Other

    savesctl completion bash|zsh|fish|powershell
    savesctl version
    savesctl help <cmd>
