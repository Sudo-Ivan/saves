# saves-sdk (C++17)

Blocking client for the saves save-sync server. libcurl + vendored nlohmann/json
and SHA-256 in third_party.

## Build

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
# or plain g++
g++ -std=c++17 -O2 -Iinclude -Ithird_party src/client.cpp src/push_pull.cpp -lcurl -lpthread
```

## Quick start

```cpp
saves::Client c({"https://saves.example.com", "sv1_..."});
auto head = saves::push(c, "mygame", "saves", "./saves", saves::PushOptions{});
saves::pull(c, "mygame", "saves", head, "./restored", saves::PullOptions{});
```

## Errors

Failures throw saves::Error with status, code, title, detail, request_id,
retry_after_seconds and optional head on a 409 conflict.

## Thread safety

A Client is safe to share; every call builds its own curl easy handle.

## Not covered

Client-side vault encryption is not implemented; encrypted manifests are
refused. Use savesctl for vault snapshots.
