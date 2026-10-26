# saves-sdk (Rust)

Blocking client for the saves save-sync server.

## Install

```toml
saves-sdk = { git = "https://github.com/Sudo-Ivan/saves" }
```

## Quick start

```rust
let c = saves_sdk::Client::new("https://saves.example.com", "sv1_...");
let head = c.push("mygame", "saves", std::path::Path::new("./saves"),
    &saves_sdk::PushOptions::default())?;
c.pull("mygame", "saves", &head, std::path::Path::new("./restored"),
    &saves_sdk::PullOptions::default())?;
```

## Errors

Every failure is a `saves_sdk::Error` carrying `status`, `code` (the stable
problem code), `title`, `detail`, `request_id`, `retry_after` and `head`
on a 409 conflict.

## Options

`timeout`, `retries`, `user_agent` on `Client`. `PushOptions` for root,
label, device, force, chunk size and progress. `PullOptions` for prune
and progress.

## Not covered

Client-side vault encryption is not implemented; encrypted manifests are
refused with an encrypted error. Use savesctl for vault snapshots.
