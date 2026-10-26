// SPDX-License-Identifier: 0BSD
#include <cassert>

#include "saves/push_pull.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

int main() {
    const char *url = std::getenv("SAVES_URL");
    const char *tok = std::getenv("SAVES_TOKEN");
    if (!url || !tok) {
        std::cout << "skipped: SAVES_URL or SAVES_TOKEN unset\n";
        return 0;
    }
    saves::Client c({url, tok});
    auto me = c.me_json();
    assert(!me.empty());

    auto base = std::filesystem::temp_directory_path() / "sdk-cpp-in";
    std::filesystem::create_directories(base / "empty");
    std::ofstream(base / "hello.txt") << "hi";
    {
        std::ofstream f(base / "big.bin", std::ios::binary);
        std::vector<char> big(3 << 20, 7);
        f.write(big.data(), big.size());
    }
    auto head = saves::push(c, "sdk-cpp", "saves", base, saves::PushOptions{});
    assert(!head.empty());

    auto out = std::filesystem::temp_directory_path() / "sdk-cpp-out";
    saves::pull(c, "sdk-cpp", "saves", head, out, saves::PullOptions{});
    {
        std::ifstream f(out / "save" / "hello.txt");
        std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        assert(s == "hi");
    }
    {
        std::ifstream f(out / "save" / "big.bin", std::ios::binary);
        std::vector<char> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        assert(b.size() == (3 << 20) && b[0] == 7);
    }
    assert(std::filesystem::is_directory(out / "save" / "empty"));

    auto t = c.create_token("sdk-cpp", {"read"});
    (void)t;
    std::filesystem::remove_all(base);
    std::filesystem::remove_all(out);
    std::cout << "integration passed\n";
    return 0;
}
