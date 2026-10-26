// SPDX-License-Identifier: 0BSD

import assert from "node:assert";
import { createServer } from "node:http";
import { test } from "node:test";
import { SavesClient } from "../src/client.js";
import { SavesError } from "../src/errors.js";

import type { IncomingMessage, ServerResponse } from "node:http";

function mock(handler: (req: IncomingMessage, res: ServerResponse) => void) {
  return new Promise<string>((resolve) => {
    const s = createServer((req, res) => handler(req, res));
    s.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(s.address() as { port: number }).port}`));
    s.unref();
  });
}

test("problem+json parsed", async () => {
  const url = await mock((_, res) => {
    res.statusCode = 404;
    res.setHeader("content-type", "application/problem+json");
    res.end(JSON.stringify({ status: 404, code: "not_found", title: "nf", detail: "d" }));
  });
  const c = new SavesClient({ baseUrl: url, token: "sv1_x" });
  let e!: SavesError;
  try { await c.me(); assert.fail("should throw"); } catch (err) { e = err as SavesError; }
  assert.equal(e.status, 404);
  assert.equal(e.code, "not_found");
});

test("429 retried", async () => {
  let n = 0;
  const url = await mock((_, res) => {
    n++;
    if (n < 3) {
      res.statusCode = 429;
      res.setHeader("retry-after", "0");
      res.end(JSON.stringify({ status: 429, code: "rate_limited" }));
    } else {
      res.setHeader("content-type", "application/json");
      res.end("{}");
    }
  });
  const c = new SavesClient({ baseUrl: url, token: "t", retries: 3 });
  await c.me();
  assert.equal(n, 3);
});

test("token redacted", () => {
  const c = new SavesClient({ baseUrl: "http://x", token: "sv1_secret" });
  assert.ok(!c.toString().includes("sv1_secret"));
});
