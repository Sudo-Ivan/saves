// SPDX-License-Identifier: 0BSD

import com.sun.net.httpserver.HttpServer;
import io.github.sudoivan.saves.SavesClient;
import io.github.sudoivan.saves.SavesException;
import io.github.sudoivan.saves.internal.Json;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

public class TestOffline {

    static HttpServer mock(int status, String body) throws IOException {
        var srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/", e -> {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            e.getResponseHeaders().add("Content-Type", "application/problem+json");
            e.sendResponseHeaders(status, b.length);
            try (OutputStream os = e.getResponseBody()) { os.write(b); }
        });
        srv.start();
        return srv;
    }

    public static void main(String[] args) throws Exception {
        // json parsing
        var v = Json.parse("{\"a\":[1,true,null,\"x\"],\"b\":{}}");
        assertTrue(v instanceof java.util.Map, "json map");
        try { Json.parse("{bad"); assertTrue(false, "bad json"); } catch (IllegalArgumentException e) { }

        // problem parsing
        var srv = mock(404, "{\"type\":\"about:blank\",\"title\":\"nf\",\"status\":404,\"code\":\"not_found\",\"detail\":\"d\"}");
        var c = SavesClient.builder().baseUrl("http://127.0.0.1:" + srv.getAddress().getPort()).token("sv1_x").retries(0).build();
        try { c.me(); assertTrue(false, "should throw"); }
        catch (SavesException e) {
            assertTrue(e.status() == 404, "status");
            assertTrue(e.code().equals("not_found"), "code");
        }
        srv.stop(0);

        // 429 retry
        var calls = new AtomicInteger();
        var srv2 = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv2.createContext("/v1/me", e -> {
            int n = calls.incrementAndGet();
            byte[] b = n < 3 ? "{\"code\":\"rate_limited\"}".getBytes() : "{}".getBytes();
            e.getResponseHeaders().add("Retry-After", "0");
            e.sendResponseHeaders(n < 3 ? 429 : 200, b.length);
            try (OutputStream os = e.getResponseBody()) { os.write(b); }
        });
        srv2.start();
        var c2 = SavesClient.builder().baseUrl("http://127.0.0.1:" + srv2.getAddress().getPort()).token("t").retries(3).build();
        c2.me();
        srv2.stop(0);
        assertTrue(calls.get() == 3, "retry count " + calls.get());

        // redaction
        var c3 = SavesClient.builder().baseUrl("http://x").token("sv1_secret").build();
        assertTrue(!c3.toString().contains("sv1_secret"), "redacted");

        System.out.println("offline tests passed");
    }

    static void assertTrue(boolean b, String m) {
        if (!b) throw new AssertionError(m);
    }
}
