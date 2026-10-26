// SPDX-License-Identifier: 0BSD

#include "saves/client.hpp"
#include "sha256.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <cstring>
#include <sstream>
#include <thread>

namespace saves {

using json = nlohmann::json;

static size_t write_cb(void *ptr, size_t sz, size_t n, void *ud) {
    auto *v = static_cast<std::vector<uint8_t> *>(ud);
    v->insert(v->end(), static_cast<uint8_t *>(ptr), static_cast<uint8_t *>(ptr) + sz * n);
    return sz * n;
}

struct Client::Impl {
    Options o;
    explicit Impl(Options o2) : o(std::move(o2)) { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~Impl() { }

    struct Res {
        long status = 0;
        std::vector<uint8_t> body;
        std::string rid;
        long ra = -1;
    };

    static bool idempotent(const char *m, const std::string &p) {
        std::string ms(m);
        return ms == "GET" || ms == "HEAD" || ms == "DELETE" ||
               (ms == "PUT" && p.find("/chunks/") != std::string::npos);
    }

    Res call(const char *method, const std::string &path, const std::string &ct,
             const std::vector<uint8_t> &body, const std::vector<std::pair<std::string, std::string>> &hdrs) {
        bool idem = idempotent(method, path);
        for (int att = 0;; att++) {
            CURL *c = curl_easy_init();
            Res res;
            std::string url = o.base_url + path;
            struct curl_slist *hs = nullptr;
            hs = curl_slist_append(hs, ("Authorization: Bearer " + o.token).c_str());
            hs = curl_slist_append(hs, "Accept: application/json");
            for (auto &h : hdrs) hs = curl_slist_append(hs, (h.first + ": " + h.second).c_str());
            if (!o.user_agent.empty()) curl_easy_setopt(c, CURLOPT_USERAGENT, o.user_agent.c_str());
            curl_easy_setopt(c, CURLOPT_HTTPHEADER, hs);
            curl_easy_setopt(c, CURLOPT_URL, url.c_str());
            curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method);
            curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
            curl_easy_setopt(c, CURLOPT_WRITEDATA, &res.body);
            curl_easy_setopt(c, CURLOPT_TIMEOUT, static_cast<long>(o.timeout_seconds));
            curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
            if (!body.empty()) {
                hs = curl_slist_append(hs, ("Content-Type: " + ct).c_str());
                curl_easy_setopt(c, CURLOPT_POSTFIELDS, reinterpret_cast<const char *>(body.data()));
                curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
            }
            // capture response headers
            auto hcb = [](char *b, size_t sz, size_t n, void *ud) -> size_t {
                auto *r = static_cast<Res *>(ud);
                std::string line(b, sz * n);
                if (line.rfind("X-Request-Id:", 0) == 0 || line.rfind("x-request-id:", 0) == 0)
                    r->rid = line.substr(line.find(':') + 1);
                if (line.rfind("Retry-After:", 0) == 0 || line.rfind("retry-after:", 0) == 0)
                    r->ra = std::atol(line.substr(line.find(':') + 1).c_str());
                return sz * n;
            };
            curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, +hcb);
            curl_easy_setopt(c, CURLOPT_HEADERDATA, &res);
            CURLcode cc = curl_easy_perform(c);
            res.status = cc == CURLE_OK ? ([&] { long s; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &s); return s; })() : 0;
            curl_slist_free_all(hs);
            curl_easy_cleanup(c);
            if (cc != CURLE_OK) {
                if (idem && att < o.retries) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500 * (att + 1)));
                    continue;
                }
                throw Error(0, "transport", curl_easy_strerror(cc));
            }
            if (res.status == 429 || res.status == 503 || (idem && res.status >= 500)) {
                if (att < o.retries) {
                    long wait = res.ra > 0 ? res.ra * 1000 : std::min(500L * (att + 1), 10000L);
                    std::this_thread::sleep_for(std::chrono::milliseconds(wait));
                    continue;
                }
            }
            if (res.status >= 400) {
                Error e(static_cast<int>(res.status), "internal", "error");
                e.request_id = res.rid;
                e.retry_after_seconds = res.ra;
                try {
                    auto v = json::parse(std::string(res.body.begin(), res.body.end()));
                    e.code = v.value("code", e.code);
                    e.title = v.value("title", e.title);
                    e.detail = v.value("detail", std::string());
                    if (v.contains("head") && v["head"].is_string()) e.head = v["head"].get<std::string>();
                } catch (...) {}
                throw e;
            }
            return res;
        }
    }
};

Client::Client(Options opts) : impl_(std::make_unique<Impl>(std::move(opts))) {}
Client::~Client() = default;

static std::string enc(const std::string &s) {
    std::string out;
    for (char ch : s) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~')
            out += ch;
        else {
            char buf[4];
            snprintf(buf, sizeof buf, "%%%02X", static_cast<unsigned char>(ch));
            out += buf;
        }
    }
    return out;
}

static std::string jstr(const std::vector<uint8_t> &b) { return std::string(b.begin(), b.end()); }

std::string Client::me_json() { return jstr(impl_->call("GET", "/v1/me", "", {}, {}).body); }
std::string Client::list_apps_json() { return jstr(impl_->call("GET", "/v1/apps", "", {}, {}).body); }
std::string Client::get_slot_json(const std::string &app, const std::string &slot) {
    return jstr(impl_->call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot), "", {}, {}).body);
}

Manifest Client::get_manifest(const std::string &app, const std::string &slot, const std::string &id) {
    auto v = json::parse(jstr(impl_->call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(id), "", {}, {}).body));
    Manifest m;
    m.enc = v.contains("enc") && !v["enc"].is_null();
    m.device = v.value("device", "");
    m.label = v.value("label", "");
    if (v.contains("parent") && v["parent"].is_string()) m.parent = v["parent"].get<std::string>();
    for (auto &d : v.value("dirs", json::array())) m.dirs.push_back(d.get<std::string>());
    for (auto &f : v["files"]) {
        FileEntry fe;
        fe.path = f.value("path", "");
        fe.size = f.value("size", (int64_t)0);
        fe.mode = f.value("mode", 0);
        fe.mtime_ns = f.value("mtime_ns", (int64_t)0);
        if (f.contains("inline") && f["inline"].is_string()) fe.inline_b64 = f["inline"].get<std::string>();
        for (auto &c : f.value("chunks", json::array()))
            fe.chunks.push_back(ChunkRef{c.value("h", ""), c.value("n", (uint32_t)0)});
        m.files.push_back(std::move(fe));
    }
    return m;
}

BeginOut Client::begin_snapshot(const std::string &app, const std::string &slot, const std::string &if_match, const Manifest &m) {
    json v = {{"version", 1}, {"files", json::array()}};
    if (!m.device.empty()) v["device"] = m.device;
    if (!m.label.empty()) v["label"] = m.label;
    if (m.parent) v["parent"] = *m.parent;
    if (!m.dirs.empty()) v["dirs"] = m.dirs;
    for (auto &f : m.files) {
        json fj = {{"path", f.path}, {"size", f.size}, {"mode", f.mode}, {"mtime_ns", f.mtime_ns}};
        if (!f.inline_b64.empty()) fj["inline"] = f.inline_b64;
        else {
            json cs = json::array();
            for (auto &c : f.chunks) cs.push_back({{"h", c.h}, {"n", c.n}});
            fj["chunks"] = cs;
        }
        v["files"].push_back(fj);
    }
    std::string b = v.dump();
    std::vector<std::pair<std::string, std::string>> hdrs;
    if (!if_match.empty()) hdrs.push_back({"If-Match", if_match});
    auto r = impl_->call("POST", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots", "application/json", {b.begin(), b.end()}, hdrs);
    auto out = json::parse(jstr(r.body));
    BeginOut bo;
    bo.id = out.value("id", "");
    for (auto &h : out.value("missing", json::array())) bo.missing.push_back(h.get<std::string>());
    return bo;
}

void Client::put_chunk(const std::string &app, const std::string &slot, const std::string &snap, const std::string &hash, const std::vector<uint8_t> &data) {
    impl_->call("PUT", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(snap) + "/chunks/" + hash,
                "application/octet-stream", data, {});
}

std::string Client::commit_snapshot(const std::string &app, const std::string &slot, const std::string &id, const std::string &if_match, bool force) {
    std::string p = "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(id) + "/commit";
    if (force) p += "?force=1";
    std::vector<std::pair<std::string, std::string>> hdrs;
    if (!if_match.empty()) hdrs.push_back({"If-Match", if_match});
    auto r = impl_->call("POST", p, "", {}, hdrs);
    try {
        auto v = json::parse(jstr(r.body));
        return v.value("head", id);
    } catch (...) { return id; }
}

void Client::delete_snapshot(const std::string &app, const std::string &slot, const std::string &id) {
    impl_->call("DELETE", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(id), "", {}, {});
}

std::vector<uint8_t> Client::get_chunk(const std::string &app, const std::string &hash, std::pair<uint64_t, uint64_t> range) {
    std::vector<std::pair<std::string, std::string>> hdrs;
    if (range.second > range.first || range.first > 0)
        hdrs.push_back({"Range", "bytes=" + std::to_string(range.first) + "-" + std::to_string(range.second)});
    return impl_->call("GET", "/v1/apps/" + enc(app) + "/chunks/" + hash, "", {}, hdrs).body;
}

std::vector<uint8_t> Client::get_file(const std::string &app, const std::string &slot, const std::string &snap, const std::string &path) {
    std::string ep;
    for (auto &seg : [&] { std::vector<std::string> s; size_t st = 0; for (size_t i = 0; i <= path.size(); ++i) if (i == path.size() || path[i] == '/') { s.push_back(path.substr(st, i - st)); st = i + 1; } return s; }())
        ep += "/" + enc(seg);
    return impl_->call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(snap) + "/files" + ep, "", {}, {}).body;
}

void Client::download_archive(const std::string &app, const std::string &slot, const std::string &snap, std::ostream &out) {
    auto b = impl_->call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(snap) + "/archive.tar", "", {}, {});
    out.write(reinterpret_cast<const char *>(b.body.data()), static_cast<std::streamsize>(b.body.size()));
}

std::string Client::create_token(const std::string &name, const std::vector<std::string> &scopes) {
    json v = {{"name", name}, {"scopes", scopes}};
    std::string b = v.dump();
    auto r = impl_->call("POST", "/v1/tokens", "application/json", {b.begin(), b.end()}, {});
    return jstr(r.body);
}
void Client::patch_token(const std::string &id, const std::string &json_patch) {
    impl_->call("PATCH", "/v1/tokens/" + enc(id), "application/json", {json_patch.begin(), json_patch.end()}, {});
}
void Client::revoke_token(const std::string &id) {
    impl_->call("DELETE", "/v1/tokens/" + enc(id), "", {}, {});
}

std::string Client::diff(const std::string &app, const std::string &slot, const std::string &a, const std::string &b) {
    return jstr(impl_->call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(a) + "/diff/" + enc(b), "", {}, {}).body);
}

std::string Client::vault_get() { return jstr(impl_->call("GET", "/v1/vault", "", {}, {}).body); }

void Client::vault_put(const std::string &json_record) {
    impl_->call("PUT", "/v1/vault", "application/json", {json_record.begin(), json_record.end()}, {});
}

void Client::vault_delete() { impl_->call("DELETE", "/v1/vault", "", {}, {}); }

std::string Client::token_events(const std::string &id) {
    return jstr(impl_->call("GET", "/v1/tokens/" + enc(id) + "/events", "", {}, {}).body);
}

std::string Client::token_stats(const std::string &id) {
    return jstr(impl_->call("GET", "/v1/tokens/" + enc(id) + "/stats", "", {}, {}).body);
}

std::string Client::list_tokens() { return jstr(impl_->call("GET", "/v1/tokens", "", {}, {}).body); }

std::string Client::get_token(const std::string &id) {
    return jstr(impl_->call("GET", "/v1/tokens/" + enc(id), "", {}, {}).body);
}

void Client::stream_events(std::function<void(const SseEvent &)> cb, std::function<bool()> stop) {
    std::string last;
    long backoff = 500;
    while (!stop()) {
        auto r = impl_->call("GET", "/v1/events", "", {}, {{"Accept", "text/event-stream"}});
        std::istringstream is(jstr(r.body));
        std::string line, name, data;
        while (std::getline(is, line) && !stop()) {
            if (line.empty()) {
                if (!data.empty()) cb(SseEvent{last, name.empty() ? "message" : name, data});
                name.clear(); data.clear();
            } else if (line.rfind("event:", 0) == 0) name = line.substr(6);
            else if (line.rfind("data:", 0) == 0) data = line.substr(5);
            else if (line.rfind("id:", 0) == 0) last = line.substr(3);
        }
        backoff = std::min(backoff * 2, 10000L);
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff + backoff / 4 * static_cast<long>(std::rand() % 1000) / 1000));
    }
}

} // namespace saves
