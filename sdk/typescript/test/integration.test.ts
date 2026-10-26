// SPDX-License-Identifier: 0BSD

import assert from "node:assert";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { SavesClient } from "../src/index.js";
import { pull, push } from "../src/node.js";

const url = process.env.SAVES_URL;
const tok = process.env.SAVES_TOKEN;

test("roundtrip", async (t) => {
  if (!url || !tok) { t.skip("SAVES_URL or SAVES_TOKEN unset"); return; }
  const c = new SavesClient({ baseUrl: url, token: tok });
  assert.ok(await c.me());
  const dir = await mkdtemp(join(tmpdir(), "ts-sdk-in-"));
  await mkdir(join(dir, "empty"), { recursive: true });
  await writeFile(join(dir, "hello.txt"), "hi");
  const big = Buffer.alloc(3 << 20, 7);
  await writeFile(join(dir, "big.bin"), big);
  const head = await push(c, { app: "sdk-ts", slot: "saves", dir, device: "test" });
  assert.ok(head);
  const out = await mkdtemp(join(tmpdir(), "ts-sdk-out-"));
  await pull(c, { app: "sdk-ts", slot: "saves", snapshotId: head, dir: out });
  assert.equal(await readFile(join(out, "save", "hello.txt"), "utf8"), "hi");
  assert.deepEqual(await readFile(join(out, "save", "big.bin")), big);
  assert.ok(await mkdir(join(out, "save", "empty"), { recursive: true }));
  const tok2 = await c.createToken("ts", ["read"]) as { id: string };
  await c.patchToken(tok2.id, { name: "ts2" });
  await c.revokeToken(tok2.id);
});
