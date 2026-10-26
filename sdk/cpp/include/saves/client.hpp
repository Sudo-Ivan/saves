// SPDX-License-Identifier: 0BSD

#pragma once

#include "errors.hpp"
#include "models.hpp"

#include <functional>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace saves {

/// Client for the saves API. Thread safe; each call builds its own curl handle.
class Client {
public:
    explicit Client(Options opts);
    ~Client();
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    // identity
    std::string me_json();

    // apps and slots
    std::string list_apps_json();
    std::string get_slot_json(const std::string &app, const std::string &slot);

    // snapshots
    Manifest get_manifest(const std::string &app, const std::string &slot, const std::string &id);
    BeginOut begin_snapshot(const std::string &app, const std::string &slot, const std::string &if_match, const Manifest &m);
    void put_chunk(const std::string &app, const std::string &slot, const std::string &snap, const std::string &hash, const std::vector<uint8_t> &data);
    std::string commit_snapshot(const std::string &app, const std::string &slot, const std::string &id, const std::string &if_match, bool force);
    void delete_snapshot(const std::string &app, const std::string &slot, const std::string &id);

    // reads
    std::vector<uint8_t> get_chunk(const std::string &app, const std::string &hash, std::pair<uint64_t, uint64_t> range = {0, 0});
    std::vector<uint8_t> get_file(const std::string &app, const std::string &slot, const std::string &snap, const std::string &path);
    void download_archive(const std::string &app, const std::string &slot, const std::string &snap, std::ostream &out);

    // diff and vault
    std::string diff(const std::string &app, const std::string &slot, const std::string &a, const std::string &b);
    std::string vault_get();
    void vault_put(const std::string &json_record);
    void vault_delete();

    // tokens
    std::string create_token(const std::string &name, const std::vector<std::string> &scopes);
    void patch_token(const std::string &id, const std::string &json_patch);
    void revoke_token(const std::string &id);
    std::string token_events(const std::string &id);
    std::string token_stats(const std::string &id);
    std::string list_tokens();
    std::string get_token(const std::string &id);

    // events stream; callback gets each event; runs until stop() or error
    void stream_events(std::function<void(const SseEvent &)> cb, std::function<bool()> stop);

private:
    Options opts_;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace saves
