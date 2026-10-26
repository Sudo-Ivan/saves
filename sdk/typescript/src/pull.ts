// SPDX-License-Identifier: 0BSD

import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, rename, rm, stat, utimes, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { SavesClient } from "./client.js";
import { SavesError } from "./errors.js";
import type { PullOptions } from "./push.js";

function safePath(p: string): void {
  if (p.startsWith("/") || p.includes("\\") ||
      p.split("/").some(s => s === "" || s === "." || s === ".."))
    throw new SavesError("unsafe path");
}

function sha256hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

function b64d(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

/** Downloads a snapshot into a directory. */
export async function pull(c: SavesClient, o: PullOptions): Promise<void> {
  const m = await c.getManifest(o.app, o.slot, o.snapshotId);
  if (m.enc) {
    const e = new SavesError("snapshot is encrypted");
    e.status = 409; e.code = "encrypted";
    throw e;
  }
  const seen = new Set<string>();
  let total = 0, done = 0;
  for (const f of m.files) total += f.size;
  for (const f of m.files) {
    safePath(f.path);
    const dst = join(o.dir, f.path);
    await mkdir(dirname(dst), { recursive: true });
    let data: Uint8Array;
    if (f.inline) {
      data = b64d(f.inline);
    } else {
      const chs = f.chunks ?? [];
      const parts = await Promise.all(chs.map(async ch => {
        const b = new Uint8Array(await c.getChunk(o.app, ch.h));
        if (sha256hex(b) !== ch.h) throw new SavesError("chunk hash mismatch");
        return b;
      }));
      data = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let off = 0;
      for (const p of parts) { data.set(p, off); off += p.length; }
    }
    if (data.length !== f.size) throw new SavesError("size mismatch");
    const tmp = dst + ".saves-tmp";
    await writeFile(tmp, data);
    try { await chmod(tmp, f.mode & 0o777); } catch { /* best effort */ }
    await rename(tmp, dst);
    try { await utimes(dst, f.mtime_ns / 1e9, f.mtime_ns / 1e9); } catch { /* best effort */ }
    seen.add(dst);
    done += f.size;
    o.onProgress?.(done, total);
  }
  for (const d of m.dirs ?? []) {
    const p = join(o.dir, d);
    await mkdir(p, { recursive: true });
    seen.add(p);
  }
  if (o.prune) {
    for (const ent of await readdir(o.dir, { recursive: true, withFileTypes: true })) {
      const p = join(o.dir, ent.name);
      if (ent.isFile() && !seen.has(p)) await rm(p);
    }
  }
}
