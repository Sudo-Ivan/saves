// SPDX-License-Identifier: 0BSD

import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { SavesClient } from "./client.js";
import { SavesError } from "./errors.js";
import type { ChunkRef, FileEntry, Manifest } from "./models.js";

export interface PushOptions {
  app: string;
  slot: string;
  dir: string;
  root?: string;
  label?: string;
  device?: string;
  force?: boolean;
  chunkSize?: number;
  parallelism?: number;
  onProgress?: (done: number, total: number) => void;
  signal?: AbortSignal;
}

export interface PullOptions {
  app: string;
  slot: string;
  snapshotId: string;
  dir: string;
  prune?: boolean;
  onProgress?: (done: number, total: number) => void;
  signal?: AbortSignal;
}

interface WalkFile {
  rel: string;
  full: string;
  size: number;
  mode: number;
  mtimeNs: number;
}

function safePath(p: string): void {
  if (p.startsWith("/") || p.includes("\\") ||
      p.split("/").some(s => s === "" || s === "." || s === ".."))
    throw new SavesError("unsafe path");
}

function sha256hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

async function walk(base: string, rel: string, out: WalkFile[], dirs: string[]): Promise<void> {
  const p = rel ? join(base, rel) : base;
  const ents = await readdir(p, { withFileTypes: true });
  ents.sort((a, b) => a.name.localeCompare(b.name));
  for (const e of ents) {
    if (e.isSymbolicLink()) continue;
    const rp = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) {
      dirs.push(rp);
      await walk(base, rp, out, dirs);
    } else {
      const st = await stat(join(p, e.name));
      out.push({
        rel: rp, full: join(p, e.name), size: st.size,
        mode: st.mode & 0o777, mtimeNs: Math.round(st.mtimeMs * 1e6),
      });
    }
  }
}

/** Uploads a directory as a snapshot. Returns the committed head id. */
export async function push(c: SavesClient, o: PushOptions): Promise<string> {
  const root = o.root ?? "save";
  const par = o.parallelism ?? 4;
  const me = await c.me() as { limits: Record<string, number> };
  const lim = me.limits;
  const inlineMax = lim.inline_max_bytes ?? 64 * 1024;
  const cs = Math.min(Math.max(o.chunkSize ?? 1 << 20,
    lim.min_chunk_bytes ?? 256 << 10), lim.max_chunk_bytes ?? 8 << 20);

  const files: WalkFile[] = [];
  const dirs: string[] = [];
  await walk(o.dir, "", files, dirs);
  files.sort((a, b) => a.rel.localeCompare(b.rel));

  const mfiles: FileEntry[] = [];
  const chunks: { h: string; file: string; off: number; len: number }[] = [];
  let total = 0;
  for (const f of files) {
    total += f.size;
    const fe: FileEntry = { path: `${root}/${f.rel}`, size: f.size, mode: f.mode, mtime_ns: f.mtimeNs };
    if (f.size <= inlineMax) {
      fe.inline = Buffer.from(await readFile(f.full)).toString("base64");
    } else {
      const data = await readFile(f.full);
      const refs: ChunkRef[] = [];
      for (let off = 0; off < data.length; off += cs) {
        const c = data.subarray(off, Math.min(off + cs, data.length));
        const h = sha256hex(c);
        refs.push({ h, n: c.length });
        chunks.push({ h, file: f.full, off, len: c.length });
      }
      fe.chunks = refs;
    }
    mfiles.push(fe);
  }

  let head = "";
  try {
    const s = await c.getSlot(o.app, o.slot);
    head = String(s.head ?? "");
  } catch { /* no slot yet */ }
  const m: Manifest = {
    version: 1, device: o.device ?? "", label: o.label ?? "",
    ...(head ? { parent: head } : {}),
    dirs: dirs.length ? dirs : undefined, files: mfiles,
  };
  const bo = await c.beginSnapshot(o.app, o.slot, head || undefined, m);

  const miss = new Set(bo.missing ?? []);
  const jobs = chunks.filter(j => miss.has(j.h));
  let done = 0;
  const workers = Array.from({ length: par }, async () => {
    for (;;) {
      const j = jobs.shift();
      if (!j) return;
      const buf = Buffer.alloc(j.len);
      const fd = await import("node:fs/promises").then(m => m.open(j.file, "r"));
      await fd.read(buf, 0, j.len, j.off);
      await fd.close();
      await c.putChunk(o.app, o.slot, bo.id, j.h, buf, o.signal);
      done += j.len;
      o.onProgress?.(done, total);
    }
  });
  await Promise.all(workers);
  const res = await c.commitSnapshot(o.app, o.slot, bo.id, { ifMatch: head || undefined, force: o.force });
  return String(res.head ?? bo.id);
}
