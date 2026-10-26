# @saves/sdk (TypeScript)

Async client for the saves save-sync server. Node 18+ and browsers
(push and pull live behind the @saves/sdk/node entry).

## Install

```sh
pnpm add @saves/sdk
```

## Quick start

```ts
import { SavesClient } from "@saves/sdk";
import { push, pull } from "@saves/sdk/node";

const c = new SavesClient({ baseUrl: "https://saves.example.com", token: "sv1_..." });
const head = await push(c, { app: "mygame", slot: "saves", dir: "./saves" });
await pull(c, { app: "mygame", slot: "saves", snapshotId: head, dir: "./restored" });
```

## Errors

Failures throw SavesError with status, code, title, detail, requestId,
retryAfter and head on a 409 conflict.

## Options

ClientOptions: baseUrl, token, timeoutMs, retries, userAgent, fetch.
PushOptions: root, label, device, force, chunkSize, parallelism, onProgress, signal.
PullOptions: prune, onProgress, signal.

## Browser vs node

The client works in browsers via the injected fetch. push and pull use
node:fs and node:crypto so they are exported from @saves/sdk/node only.
