// SPDX-License-Identifier: 0BSD

#include "saves/client.hpp"
#include "sha256.hpp"

#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// tiny one-shot mock server: reads the request headers then sends a canned reply.
static std::string mock(int status, const std::string &reason, const std::string &body) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    a.sin_port = 0;
    bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof a);
    socklen_t al = sizeof a;
    getsockname(fd, reinterpret_cast<sockaddr *>(&a), &al);
    int port = ntohs(a.sin_port);
    listen(fd, 4);
    std::thread([fd, status, reason, body] {
        for (;;) {
            int c = accept(fd, nullptr, nullptr);
            if (c < 0) return;
            char buf[4096];
            recv(c, buf, sizeof buf, 0);
            std::string r = "HTTP/1.1 " + std::to_string(status) + " " + reason +
                            "\r\nContent-Length: " + std::to_string(body.size()) +
                            "\r\nContent-Type: application/problem+json\r\n\r\n" + body;
            send(c, r.c_str(), r.size(), 0);
            close(c);
        }
    }).detach();
    return "http://127.0.0.1:" + std::to_string(port);
}

int main() {
    // sha256 vectors
    auto h1 = saves::sha256_hex(reinterpret_cast<const uint8_t *>(""), 0);
    assert(h1 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    auto h2 = saves::sha256_hex(reinterpret_cast<const uint8_t *>("abc"), 3);
    assert(h2 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // problem parsing
    {
        auto u = mock(404, "Not Found", R"({"type":"about:blank","title":"nf","status":404,"code":"not_found","detail":"d"})");
        saves::Client c({u, "tok"});
        bool caught = false;
        try { c.me_json(); } catch (const saves::Error &e) {
            caught = true;
            assert(e.status == 404 && e.code == "not_found");
        }
        assert(caught);
    }
    // traversal refused is in pull; unit-level check skipped here.
    std::cout << "offline tests passed\n";
    return 0;
}
