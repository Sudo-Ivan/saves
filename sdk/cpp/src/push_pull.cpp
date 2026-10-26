// SPDX-License-Identifier: 0BSD

#include "saves/push_pull.hpp"
#include "sha256.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <mutex>
#include <set>
#include <thread>

namespace saves {

using json = nlohmann::json;

static std::string b64(const std::vector<uint8_t> &d) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < d.size(); i += 3) {
        uint32_t v = (static_cast<uint32_t>(d[i]) << 16) | (i + 1 < d.size() ? static_cast<uint32_t>(d[i + 1]) << 8 : 0) |
                     (i + 2 < d.size() ? static_cast<uint32_t>(d[i + 2]) : 0);
        out += t[(v >> 18) & 63];
        out += t[(v >> 12) & 63];
        out += i + 1 < d.size() ? t[(v >> 6) & 63] : '=';
        out += i + 2 < d.size() ? t[v & 63] : '=';
    }
    return out;
}

static void safe_path(const std::string &p) {
    if (p.empty() || p[0] == '/' || p.find('\\') != std::string::npos)
        throw Error(400, "bad_path", "unsafe path");
    size_t st = 0;
    for (size_t i = 0; i <= p.size(); ++i)
        if (i == p.size() || p[i] == '/') {
            auto seg = p.substr(st, i - st);
            if (seg.empty() || seg == "." || seg == "..") throw Error(400, "bad_path", "unsafe path");
            st = i + 1;
        }
}

struct ChunkJob {
    std::string hash, file;
    uint64_t off = 0;
    uint32_t len = 0;
};

static void walk(const std::filesystem::path &base, const std::string &root, Manifest &m,
                 std::vector<ChunkJob> &jobs, uint64_t cs, uint64_t inline_max, uint64_t &total) {
    std::vector<std::filesystem::directory_entry> ents;
    for (auto &e : std::filesystem::directory_iterator(base)) ents.push_back(e);
    std::sort(ents.begin(), ents.end(), [](auto &a, auto &b) { return a.path() < b.path(); });
    for (auto &e : ents) {
        if (e.is_symlink()) continue;
        std::string rel = root + "/" + e.path().filename().string();
        if (e.is_directory()) {
            m.dirs.push_back(rel);
            walk(e.path(), rel, m, jobs, cs, inline_max, total);
        } else if (e.is_regular_file()) {
            FileEntry fe;
            fe.path = rel;
            fe.size = static_cast<int64_t>(std::filesystem::file_size(e.path()));
            total += fe.size;
            fe.mode = static_cast<int>(std::filesystem::status(e.path()).permissions());
            fe.mtime_ns = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(e.last_write_time().time_since_epoch()).count());
            if (static_cast<uint64_t>(fe.size) <= inline_max) {
                std::ifstream f(e.path(), std::ios::binary);
                std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                fe.inline_b64 = b64(d);
            } else {
                std::ifstream f(e.path(), std::ios::binary);
                uint64_t off = 0;
                std::vector<uint8_t> buf(cs);
                while (off < static_cast<uint64_t>(fe.size)) {
                    uint32_t len = static_cast<uint32_t>(std::min<uint64_t>(cs, fe.size - off));
                    f.read(reinterpret_cast<char *>(buf.data()), len);
                    auto n = static_cast<uint32_t>(f.gcount());
                    if (n == 0) break;
                    auto h = sha256_hex(buf.data(), n);
                    fe.chunks.push_back({h, n});
                    jobs.push_back({h, e.path().string(), off, n});
                    off += n;
                }
            }
            m.files.push_back(std::move(fe));
        }
    }
}

std::string push(Client &c, const std::string &app, const std::string &slot,
                 const std::filesystem::path &dir, const PushOptions &o) {
    auto me = json::parse(c.me_json());
    auto lim = me.value("limits", json::object());
    uint64_t inline_max = lim.value("inline_max_bytes", (uint64_t)65536);
    uint64_t cs = o.chunk_size;
    cs = std::max<uint64_t>(cs, lim.value("min_chunk_bytes", (uint64_t)(256 << 10)));
    cs = std::min<uint64_t>(cs, lim.value("max_chunk_bytes", (uint64_t)(8 << 20)));

    Manifest m;
    m.device = o.device;
    m.label = o.label;
    std::vector<ChunkJob> jobs;
    uint64_t total = 0;
    walk(dir, o.root, m, jobs, cs, inline_max, total);
    std::sort(m.files.begin(), m.files.end(), [](auto &a, auto &b) { return a.path < b.path; });

    std::string head;
    try {
        auto s = json::parse(c.get_slot_json(app, slot));
        head = s.value("head", "");
    } catch (...) {}
    m.parent = head.empty() ? std::nullopt : std::optional<std::string>(head);
    auto bo = c.begin_snapshot(app, slot, head, m);

    // upload missing chunks in parallel
    std::deque<ChunkJob> q;
    std::set<std::string> miss(bo.missing.begin(), bo.missing.end());
    for (auto &j : jobs)
        if (miss.count(j.hash)) q.push_back(j);
    std::mutex mu;
    std::condition_variable cv;
    uint64_t done = 0;
    bool failed = false;
    std::string first_err;
    auto worker = [&] {
        for (;;) {
            ChunkJob j;
            {
                std::unique_lock lk(mu);
                if (q.empty() || failed) return;
                j = q.front();
                q.pop_front();
            }
            try {
                std::ifstream f(j.file, std::ios::binary);
                std::vector<uint8_t> buf(j.len);
                f.seekg(static_cast<std::streamoff>(j.off));
                f.read(reinterpret_cast<char *>(buf.data()), j.len);
                c.put_chunk(app, slot, bo.id, j.hash, buf);
                std::unique_lock lk(mu);
                done += j.len;
                if (o.on_progress) o.on_progress(done, total);
            } catch (const Error &e) {
                std::unique_lock lk(mu);
                failed = true;
                first_err = e.what();
                cv.notify_all();
                return;
            }
        }
    };
    std::vector<std::thread> ts;
    for (unsigned i = 0; i < o.parallelism; ++i) ts.emplace_back(worker);
    for (auto &t : ts) t.join();
    if (failed) throw Error(0, "upload", first_err);
    return c.commit_snapshot(app, slot, bo.id, head, o.force);
}

void pull(Client &c, const std::string &app, const std::string &slot,
          const std::string &snap_id, const std::filesystem::path &dir, const PullOptions &o) {
    auto m = c.get_manifest(app, slot, snap_id);
    if (m.enc) throw Error(409, "encrypted", "snapshot is encrypted");
    std::set<std::string> seen;
    uint64_t total = 0, done = 0;
    for (auto &f : m.files) total += f.size;
    for (auto &f : m.files) {
        safe_path(f.path);
        auto dst = dir / f.path;
        std::filesystem::create_directories(dst.parent_path());
        std::vector<uint8_t> data;
        if (!f.inline_b64.empty()) {
            // decode base64
            static const std::string t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            auto inv = [](char c) -> int { size_t i = t.find(c); return i == std::string::npos ? -1 : (int)i; };
            for (size_t i = 0; i + 3 < f.inline_b64.size(); i += 4) {
                int a = inv(f.inline_b64[i]), b = inv(f.inline_b64[i + 1]), c2 = inv(f.inline_b64[i + 2]), d = inv(f.inline_b64[i + 3]);
                if (a < 0 || b < 0) break;
                uint32_t v = (a << 18) | (b << 12) | (c2 < 0 ? 0 : c2 << 6) | (d < 0 ? 0 : d);
                data.push_back((v >> 16) & 0xff);
                if (c2 >= 0) data.push_back((v >> 8) & 0xff);
                if (d >= 0) data.push_back(v & 0xff);
            }
        } else {
            // download this file's chunks in parallel, verify and write after all pass
            std::vector<std::vector<uint8_t>> parts(f.chunks.size());
            std::atomic<bool> bad{false};
            std::atomic<size_t> idx{0};
            auto worker = [&] {
                for (;;) {
                    size_t i = idx.fetch_add(1);
                    if (i >= f.chunks.size() || bad.load()) return;
                    auto b = c.get_chunk(app, f.chunks[i].h);
                    if (sha256_hex(b.data(), b.size()) != f.chunks[i].h) { bad = true; return; }
                    parts[i] = std::move(b);
                }
            };
            unsigned n = std::min<unsigned>(4, f.chunks.size());
            std::vector<std::thread> ts;
            for (unsigned i = 0; i < n; ++i) ts.emplace_back(worker);
            for (auto &t : ts) t.join();
            if (bad) throw Error(0, "checksum", "chunk hash mismatch");
            for (auto &p : parts) data.insert(data.end(), p.begin(), p.end());
        }
        if (static_cast<int64_t>(data.size()) != f.size)
            throw Error(0, "size", "size mismatch");
        auto tmp = dst;
        tmp += ".saves-tmp";
        {
            std::ofstream out(tmp, std::ios::binary);
            out.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
        }
        std::error_code pec;
        std::filesystem::permissions(tmp, std::filesystem::perms(static_cast<unsigned>(f.mode & 0777)),
                                     std::filesystem::perm_options::replace, pec);
        std::filesystem::rename(tmp, dst);
        auto t = std::filesystem::file_time_type(std::chrono::nanoseconds(f.mtime_ns));
        std::error_code ec;
        std::filesystem::last_write_time(dst, t, ec);
        done += f.size;
        if (o.on_progress) o.on_progress(done, total);
        seen.insert(dst.string());
    }
    for (auto &d : m.dirs) {
        auto p = dir / d;
        std::filesystem::create_directories(p);
        seen.insert(p.string());
    }
    if (o.prune)
        for (auto &e : std::filesystem::recursive_directory_iterator(dir))
            if (e.is_regular_file() && !seen.count(e.path().string()))
                std::filesystem::remove(e.path());
}

} // namespace saves
