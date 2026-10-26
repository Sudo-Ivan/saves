# SPDX-License-Identifier: 0BSD
"""Integration test, skipped unless SAVES_URL and SAVES_TOKEN are set."""

import os
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from saves_sdk import SavesClient, pull, push


class TestRoundtrip(unittest.TestCase):
    def test_roundtrip(self):
        url = os.environ.get("SAVES_URL")
        tok = os.environ.get("SAVES_TOKEN")
        if not url or not tok:
            self.skipTest("SAVES_URL or SAVES_TOKEN unset")
        c = SavesClient(url, tok)
        self.assertTrue(c.me())
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in"
            (src / "empty").mkdir(parents=True)
            (src / "hello.txt").write_text("hi")
            big = bytes([7]) * (3 << 20)
            (src / "big.bin").write_bytes(big)
            head = push(c, "sdk-py", "saves", str(src), device="test")
            self.assertTrue(head)
            out = Path(d) / "out"
            pull(c, "sdk-py", "saves", head, str(out))
            self.assertEqual((out / "save" / "hello.txt").read_text(), "hi")
            self.assertEqual((out / "save" / "big.bin").read_bytes(), big)
            self.assertTrue((out / "save" / "empty").is_dir())
            t = c.create_token("py", ["read"])
            c.patch_token(t["id"], {"name": "py2"})
            c.revoke_token(t["id"])


if __name__ == "__main__":
    unittest.main()
