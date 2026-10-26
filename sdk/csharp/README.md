# Saves.Sdk (C#)

Async client for the saves save-sync server. Targets netstandard2.0 and net8.0.

## Install

```xml
<PackageReference Include="Saves.Sdk" Version="0.1.0" />
```

## Quick start

```csharp
var c = new SavesClient(new Uri("https://saves.example.com"), "sv1_...");
var head = await c.PushAsync("mygame", "saves", "./saves", new PushOptions());
await c.PullAsync("mygame", "saves", head, "./restored", new PullOptions());
```

## Errors

Failures throw SavesException with Status, Code, Title, Detail, RequestId,
RetryAfter and Head on a 409 head conflict.

## Options

SavesClientOptions: Timeout, Retries, UserAgent, Handler (for tests).
PushOptions: Root, Label, Device, Force, ChunkSize, Parallelism, Progress.
PullOptions: Prune, Progress.

## Not covered

Client-side vault encryption is not implemented; encrypted manifests are
refused. Use savesctl for vault snapshots.
