// SPDX-License-Identifier: 0BSD

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace saves {

struct ChunkRef {
    std::string h;
    uint32_t n = 0;
};

struct FileEntry {
    std::string path;
    int64_t size = 0;
    int mode = 0;
    int64_t mtime_ns = 0;
    std::vector<ChunkRef> chunks;
    std::string inline_b64;
};

struct Manifest {
    int version = 1;
    std::string device, label;
    std::optional<std::string> parent;
    bool enc = false;
    std::vector<std::string> dirs;
    std::vector<FileEntry> files;
};

struct BeginOut {
    std::string id;
    std::vector<std::string> missing;
};

struct Token {
    std::string id, user_id, name;
    std::vector<std::string> scopes, apps;
};

struct SseEvent {
    std::string id, name, data;
};

struct Options {
    std::string base_url, token, user_agent;
    int timeout_seconds = 30;
    int retries = 3;
};

struct PushOptions {
    std::string root = "save", label, device;
    bool force = false;
    uint64_t chunk_size = 1 << 20;
    unsigned parallelism = 4;
    std::function<void(uint64_t, uint64_t)> on_progress;
};

struct PullOptions {
    bool prune = false;
    std::function<void(uint64_t, uint64_t)> on_progress;
};

} // namespace saves
