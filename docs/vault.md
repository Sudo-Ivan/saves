# Vault

The vault gives end to end encryption: the server stores only
ciphertext.

## Commands

- `savesctl vault init` generates a root key, stores the header on the
  server and caches the key locally under the state dir.
- `savesctl vault unlock` loads the key with your passphrase, or with a
  recovery key via `vault recovery` output.
- `savesctl vault lock` drops the cached key.
- `savesctl vault status` shows whether the vault is enabled and the key
  is cached.
- `savesctl vault change-passphrase` rewraps the root key.
- `savesctl vault recovery new` rotates the recovery key.
- `savesctl vault verify` checks the header and key consistency.
- `savesctl vault disable` disables the vault locally.

Passphrases come from `--passphrase-file`, SAVES_VAULT_PASSPHRASE, or an
interactive prompt.

## What the server sees

With the vault on, push stores: app id, slot names, snapshot timing,
number of files, ciphertext chunk sizes, and intra-user chunk equality.
File names, contents, sizes and directory structure are hidden.

## Limitations

- The vault key cannot be rotated in place; create a new vault and
  re-push all data.
- A lost passphrase without a recovery key makes stored data
  unrecoverable.
