# SPDX-License-Identifier: 0BSD
"""Offline unit tests with an in-process http.server mock."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from saves_sdk import SavesClient, SavesError


def mock(status, body, extra=None):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("content-type", "application/problem+json" if status >= 400 else "application/json")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_port}"


class TestClient(unittest.TestCase):
    def test_problem_parsing(self):
        u = mock(404, json.dumps({"status": 404, "code": "not_found", "title": "nf", "detail": "d"}))
        c = SavesClient(u, "sv1_x")
        with self.assertRaises(SavesError) as cm:
            c.me()
        self.assertEqual(cm.exception.status, 404)
        self.assertEqual(cm.exception.code, "not_found")

    def test_retry_429(self):
        calls = []
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(1)
                if len(calls) < 3:
                    self.send_response(429)
                    self.send_header("retry-after", "0")
                    self.end_headers()
                    self.wfile.write(b'{"status":429,"code":"rate_limited"}')
                else:
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(b"{}")
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        c = SavesClient(f"http://127.0.0.1:{srv.server_port}", "t", retries=3)
        c.me()
        self.assertEqual(len(calls), 3)

    def test_redaction(self):
        c = SavesClient("http://x", "sv1_secret")
        self.assertNotIn("sv1_secret", repr(c))
        self.assertNotIn("sv1_secret", str(c))


if __name__ == "__main__":
    unittest.main()
