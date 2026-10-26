// SPDX-License-Identifier: 0BSD

#pragma once

#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>

namespace saves {

/// Error thrown on saves API failures.
struct Error : std::runtime_error {
    int status = 0;
    std::string code, title, detail, request_id;
    long retry_after_seconds = -1;
    std::optional<std::string> head;
    Error(int st, std::string c, std::string t)
        : std::runtime_error(t.empty() ? c : t), status(st), code(std::move(c)), title(std::move(t)) {}
};

} // namespace saves
