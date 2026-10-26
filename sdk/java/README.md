# saves-sdk (Java)

Blocking client for the saves save-sync server. Java 11, no third party
dependencies (java.net.http plus a small internal JSON codec).

## Install

Maven coordinates: io.github.sudoivan:saves-sdk:0.1.0, or build the jar
with `sh build.sh` (javac only).

## Quick start

```java
var c = SavesClient.builder()
    .baseUrl("https://saves.example.com").token("sv1_...").build();
var o = new Push.Options();
o.app = "mygame"; o.slot = "saves"; o.dir = Path.of("./saves");
var head = Push.run(c, o);
var p = new Pull.Options();
p.app = "mygame"; p.slot = "saves"; p.snapshotId = head; p.dir = Path.of("./out");
Pull.run(c, p);
```

## Errors

Failures throw SavesException with status, code, detail, requestId,
retryAfter and head on a 409 conflict.

## Options

Builder: baseUrl, token, timeout, retries, userAgent.
Push.Options: root, label, device, force, chunkSize, parallelism, onProgress.
Pull.Options: prune, onProgress.

## Android

java.net.http is not available on Android. An OkHttp based client is out
of scope for this package.

## Not covered

Client-side vault encryption is not implemented; encrypted manifests are
refused. Use savesctl for vault snapshots.
