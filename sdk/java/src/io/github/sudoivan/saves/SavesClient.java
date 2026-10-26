// SPDX-License-Identifier: 0BSD

package io.github.sudoivan.saves;

import io.github.sudoivan.saves.internal.Json;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Blocking client for the saves API. Thread safe. */
public final class SavesClient {

    /** Server-sent event. */
    public static final class SseEvent {
        public final String id, name, data;
        SseEvent(String id, String name, String data) { this.id = id; this.name = name; this.data = data; }
    }

    public static final class Builder {
        private String base, token, ua = "saves-sdk-java";
        private Duration timeout = Duration.ofSeconds(30);
        private int retries = 3;
        public Builder baseUrl(String u) { base = u; return this; }
        public Builder token(String t) { token = t; return this; }
        public Builder timeout(Duration d) { timeout = d; return this; }
        public Builder retries(int r) { retries = r; return this; }
        public Builder userAgent(String a) { ua = a; return this; }
        public SavesClient build() { return new SavesClient(this); }
    }

    private final String base, token, ua;
    private final int retries;
    private final HttpClient http;

    private SavesClient(Builder b) {
        base = b.base.endsWith("/") ? b.base.substring(0, b.base.length() - 1) : b.base;
        token = b.token;
        ua = b.ua;
        retries = b.retries;
        http = HttpClient.newBuilder().connectTimeout(b.timeout).build();
    }

    public static Builder builder() { return new Builder(); }

    @Override public String toString() { return "SavesClient(" + base + ")"; }

    private static boolean idempotent(String m, String path) {
        return m.equals("GET") || m.equals("HEAD") || m.equals("DELETE")
            || (m.equals("PUT") && path.contains("/chunks/"));
    }

    private SavesException problem(HttpResponse<byte[]> r, String body) {
        String code = "internal", title = "", detail = "", head = null;
        try {
            @SuppressWarnings("unchecked") var v = (Map<String, Object>) Json.parse(body);
            code = str(v.get("code"), code);
            title = str(v.get("title"), "");
            detail = str(v.get("detail"), "");
            head = v.get("head") instanceof String ? (String) v.get("head") : null;
        } catch (Exception ignored) { }
        Duration ra = r.headers().firstValue("retry-after")
            .filter(v -> !v.isEmpty())
            .map(v -> Duration.ofSeconds(Long.parseLong(v.replaceAll("[^0-9]", ""))))
            .orElse(null);
        return new SavesException(r.statusCode(), code, title, detail,
            r.headers().firstValue("x-request-id").orElse(""), ra, head);
    }

    private static String str(Object v, String dflt) { return v instanceof String ? (String) v : dflt; }

    private byte[] call(String method, String path, byte[] body, String ct, Map<String, String> hdrs) throws SavesException {
        boolean idem = idempotent(method, path);
        for (int att = 0; ; att++) {
            var req = HttpRequest.newBuilder(URI.create(base + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body))
                .header("Authorization", "Bearer " + token)
                .header("User-Agent", ua)
                .header("Accept", "application/json");
            if (!ct.isEmpty()) req.header("Content-Type", ct);
            hdrs.forEach(req::header);
            HttpResponse<byte[]> r;
            try {
                r = http.send(req.build(), HttpResponse.BodyHandlers.ofByteArray());
            } catch (IOException | InterruptedException ex) {
                if (idem && att < retries) {
                    sleep(500L * (att + 1));
                    continue;
                }
                throw new SavesException(0, "transport", ex.getMessage(), "", "", null, null);
            }
            if (r.statusCode() < 400) return r.body();
            boolean retryable = r.statusCode() == 429 || r.statusCode() == 503 || (idem && r.statusCode() >= 500);
            if (att < retries && retryable) {
                long wait = r.headers().firstValue("retry-after").map(Long::parseLong).map(s2 -> s2 * 1000)
                    .orElse(Math.min(500L * (att + 1), 10_000));
                sleep(wait);
                continue;
            }
            throw problem(r, new String(r.body(), StandardCharsets.UTF_8));
        }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20").replace("%7E", "~");
    }

    private static String segs(String p) {
        var parts = p.split("/");
        var sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append('/');
            sb.append(enc(parts[i]));
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(byte[] b) {
        return (Map<String, Object>) Json.parse(new String(b, StandardCharsets.UTF_8));
    }

    public Map<String, Object> me() { return obj(call("GET", "/v1/me", null, "", Map.of())); }

    public Object listApps() { return Json.parse(new String(call("GET", "/v1/apps", null, "", Map.of()), StandardCharsets.UTF_8)); }

    public Map<String, Object> getSlot(String app, String slot) {
        return obj(call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot), null, "", Map.of()));
    }

    public Map<String, Object> getManifest(String app, String slot, String id) {
        return obj(call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(id), null, "", Map.of()));
    }

    public Map<String, Object> beginSnapshot(String app, String slot, String ifMatch, Map<String, Object> manifest) {
        var hdrs = ifMatch != null && !ifMatch.isEmpty() ? Map.of("If-Match", ifMatch) : Map.<String, String>of();
        return obj(call("POST", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots",
            Json.write(manifest).getBytes(StandardCharsets.UTF_8), "application/json", hdrs));
    }

    public void putChunk(String app, String slot, String snap, String hash, byte[] data) {
        call("PUT", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(snap) + "/chunks/" + hash,
            data, "application/octet-stream", Map.of());
    }

    public Map<String, Object> commitSnapshot(String app, String slot, String id, String ifMatch, boolean force) {
        var p = "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(id) + "/commit" + (force ? "?force=1" : "");
        var hdrs = ifMatch != null && !ifMatch.isEmpty() ? Map.of("If-Match", ifMatch) : Map.<String, String>of();
        return obj(call("POST", p, null, "", hdrs));
    }

    public void deleteSnapshot(String app, String slot, String id) {
        call("DELETE", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(id), null, "", Map.of());
    }

    public byte[] getChunk(String app, String hash, long rangeFrom, long rangeTo) {
        var hdrs = rangeTo > rangeFrom ? Map.of("Range", "bytes=" + rangeFrom + "-" + rangeTo) : Map.<String, String>of();
        return call("GET", "/v1/apps/" + enc(app) + "/chunks/" + hash, null, "", hdrs);
    }

    public byte[] getFile(String app, String slot, String snap, String path) {
        return call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot) + "/snapshots/" + enc(snap) + "/files/" + segs(path), null, "", Map.of());
    }

    public Map<String, Object> createToken(String name, java.util.List<String> scopes) {
        return obj(call("POST", "/v1/tokens",
            Json.write(Map.of("name", name, "scopes", scopes)).getBytes(StandardCharsets.UTF_8), "application/json", Map.of()));
    }

    public void patchToken(String id, Map<String, Object> patch) {
        call("PATCH", "/v1/tokens/" + enc(id), Json.write(patch).getBytes(StandardCharsets.UTF_8), "application/json", Map.of());
    }

    public void revokeToken(String id) {
        call("DELETE", "/v1/tokens/" + enc(id), null, "", Map.of());
    }

    public Object diff(String app, String slot, String a, String b) {
        return Json.parse(new String(call("GET", "/v1/apps/" + enc(app) + "/slots/" + enc(slot)
            + "/snapshots/" + enc(a) + "/diff/" + enc(b), null, "", Map.of()), StandardCharsets.UTF_8));
    }

    public Map<String, Object> tokenEvents(String id) {
        return obj(call("GET", "/v1/tokens/" + enc(id) + "/events", null, "", Map.of()));
    }

    public Map<String, Object> tokenStats(String id) {
        return obj(call("GET", "/v1/tokens/" + enc(id) + "/stats", null, "", Map.of()));
    }

    public Object listTokens() {
        return Json.parse(new String(call("GET", "/v1/tokens", null, "", Map.of()), StandardCharsets.UTF_8));
    }

    public Map<String, Object> getToken(String id) {
        return obj(call("GET", "/v1/tokens/" + enc(id), null, "", Map.of()));
    }

    public Map<String, Object> vaultGet() {
        return obj(call("GET", "/v1/vault", null, "", Map.of()));
    }

    public void vaultPut(Map<String, Object> v) {
        call("PUT", "/v1/vault", Json.write(v).getBytes(StandardCharsets.UTF_8), "application/json", Map.of());
    }

    public void vaultDelete() {
        call("DELETE", "/v1/vault", null, "", Map.of());
    }

    public void streamEvents(Consumer<SseEvent> cb, AtomicBoolean stop) {
        var last = new String[] { "" };
        long backoff = 500;
        while (!stop.get()) {
            try {
                var body = new String(call("GET", "/v1/events", null, "",
                    last[0].isEmpty() ? Map.of("Accept", "text/event-stream")
                        : Map.of("Accept", "text/event-stream", "Last-Event-ID", last[0])), StandardCharsets.UTF_8);
                String name = "", data = "";
                for (var line : body.split("\n")) {
                    if (line.isEmpty()) {
                        if (!data.isEmpty()) cb.accept(new SseEvent(last[0], name.isEmpty() ? "message" : name, data));
                        name = ""; data = "";
                    } else if (line.startsWith("event:")) name = line.substring(6).trim();
                    else if (line.startsWith("data:")) data = line.substring(5).trim();
                    else if (line.startsWith("id:")) last[0] = line.substring(3).trim();
                }
            } catch (SavesException ignored) {
                backoff = Math.min(backoff * 2, 10_000);
                sleep(backoff + (long) (Math.random() * backoff / 4));
                continue;
            }
            backoff = 500;
            sleep(500);
        }
    }
}
