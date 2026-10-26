// SPDX-License-Identifier: 0BSD

#pragma once

#include "client.hpp"

#include <filesystem>
#include <string>

namespace saves {

/// Uploads a directory as a snapshot. Returns the committed head id.
std::string push(Client &c, const std::string &app, const std::string &slot,
                 const std::filesystem::path &dir, const PushOptions &opts);

/// Downloads a snapshot into a directory.
void pull(Client &c, const std::string &app, const std::string &slot,
          const std::string &snapshot_id, const std::filesystem::path &dir,
          const PullOptions &opts);

} // namespace saves
