# saves-sdk (Python)

Blocking client for the saves save-sync server. Standard library only,
Python 3.9+.

## Install

```sh
pip install sdk/python
```

## Quick start

```python
from saves_sdk import SavesClient, push, pull

c = SavesClient("https://saves.example.com", "sv1_...")
head = push(c, "mygame", "saves", "./saves")
pull(c, "mygame", "saves", head, "./restored")
```

## Errors

Failures raise SavesError with status, code, title, detail, request_id,
retry_after and head on a 409 conflict.

## Options

SavesClient(base_url, token, timeout, retries, user_agent).
push takes root, label, device, force, chunk_size, parallelism, on_progress.
pull takes prune and on_progress.

## Async

The client is blocking and thread safe; run calls in a thread executor
(asyncio.to_thread or run_in_executor) for async applications. There is no
asyncio dependency.

## Not covered

Client-side vault encryption is not implemented; encrypted manifests are
refused. Use savesctl for vault snapshots.
