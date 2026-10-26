// SPDX-License-Identifier: 0BSD

import { SavesError } from "./errors.js";
import type { BeginOut, ClientOptions, Manifest, SseEvent, TokenCreate } from "./models.js";

const IDEMPOTENT = new Set(["GET", "HEAD", "DELETE"]);

function enc(s: string): string { return encodeURIComponent(s); }
function segs(p: string): string { return p.split("/").map(enc).join("/"); }

export class SavesClient {
  readonly baseUrl: string;
  private readonly token: string;
  private readonly timeout: number;
  private readonly retries: number;
  private readonly ua: string;
  private readonly f: typeof globalThis.fetch;

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token;
    this.timeout = opts.timeoutMs ?? 30_000;
    this.retries = opts.retries ?? 3;
    this.ua = opts.userAgent ?? "saves-sdk-ts";
    this.f = opts.fetch ?? globalThis.fetch;
  }

  toString(): string { return `SavesClient(${this.baseUrl})`; }
  [Symbol.for("nodejs.util.inspect.custom")](): string { return this.toString(); }

  private idempotent(method: string, path: string): boolean {
    return IDEMPOTENT.has(method) || (method === "PUT" && path.includes("/chunks/"));
  }

  private async problem(r: Response): Promise<SavesError> {
    const e = new SavesError(`HTTP ${r.status}`);
    e.status = r.status;
    e.requestId = r.headers.get("x-request-id") ?? "";
    const ra = r.headers.get("retry-after");
    if (ra) e.retryAfter = parseInt(ra, 10);
    try {
      const v = await r.json() as Record<string, unknown>;
      e.code = String(v.code ?? "internal");
      e.title = String(v.title ?? "");
      e.detail = String(v.detail ?? "");
      if (typeof v.head === "string") e.head = v.head;
    } catch { /* no body */ }
    return e;
  }

  private async call(method: string, path: string, body?: BodyInit, ct?: string,
    hdrs: Record<string, string> = {}, signal?: AbortSignal): Promise<Response> {
    const idem = this.idempotent(method, path);
    for (let att = 0; ; att++) {
      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), this.timeout);
      if (signal) signal.addEventListener("abort", () => ac.abort(), { once: true });
      let r: Response;
      try {
        r = await this.f(this.baseUrl + path, {
          method,
          headers: { authorization: `Bearer ${this.token}`, "user-agent": this.ua,
            ...(ct ? { "content-type": ct } : {}), ...hdrs },
          body,
          signal: ac.signal,
        });
      } catch (err) {
        clearTimeout(t);
        if (idem && att < this.retries) {
          await new Promise(r => setTimeout(r, 500 * (att + 1)));
          continue;
        }
        const e = new SavesError(String(err));
        e.code = "transport";
        throw e;
      }
      clearTimeout(t);
      const retryable = r.status === 429 || r.status === 503 || (idem && r.status >= 500);
      if (att < this.retries && retryable) {
        const ra = parseInt(r.headers.get("retry-after") ?? "0", 10);
        await new Promise(r2 => setTimeout(r2, ra > 0 ? ra * 1000 : Math.min(500 * (att + 1), 10_000)));
        continue;
      }
      if (!r.ok) throw await this.problem(r);
      return r;
    }
  }

  async me(): Promise<unknown> { return (await this.call("GET", "/v1/me")).json(); }
  async register(invite?: string): Promise<unknown> {
    return (await this.call("POST", "/v1/register", JSON.stringify({ invite }), "application/json")).json();
  }
  async listApps(): Promise<unknown> { return (await this.call("GET", "/v1/apps")).json(); }
  async listSlots(app: string): Promise<unknown> {
    return (await this.call("GET", `/v1/apps/${enc(app)}/slots`)).json();
  }
  async getSlot(app: string, slot: string): Promise<Record<string, unknown>> {
    return (await this.call("GET", `/v1/apps/${enc(app)}/slots/${enc(slot)}`)).json();
  }
  async deleteSlot(app: string, slot: string): Promise<void> {
    await this.call("DELETE", `/v1/apps/${enc(app)}/slots/${enc(slot)}`);
  }
  async listSnapshots(app: string, slot: string): Promise<unknown> {
    return (await this.call("GET", `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots`)).json();
  }
  async getManifest(app: string, slot: string, id: string): Promise<Manifest> {
    return (await this.call("GET", `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots/${enc(id)}`)).json();
  }
  async beginSnapshot(app: string, slot: string, ifMatch: string | undefined, m: Manifest): Promise<BeginOut> {
    return (await this.call("POST", `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots`,
      JSON.stringify(m), "application/json", ifMatch ? { "if-match": ifMatch } : {})).json();
  }
  async putChunk(app: string, slot: string, snap: string, hash: string, data: ArrayBuffer | Uint8Array, signal?: AbortSignal): Promise<void> {
    await this.call("PUT", `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots/${enc(snap)}/chunks/${hash}`,
      data as BodyInit, "application/octet-stream", {}, signal);
  }
  async commitSnapshot(app: string, slot: string, id: string, opts: { ifMatch?: string; force?: boolean } = {}): Promise<Record<string, unknown>> {
    let p = `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots/${enc(id)}/commit`;
    if (opts.force) p += "?force=1";
    return (await this.call("POST", p, undefined, undefined,
      opts.ifMatch ? { "if-match": opts.ifMatch } : {})).json();
  }
  async deleteSnapshot(app: string, slot: string, id: string): Promise<void> {
    await this.call("DELETE", `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots/${enc(id)}`);
  }
  async diff(app: string, slot: string, a: string, b: string): Promise<unknown> {
    return (await this.call("GET", `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots/${enc(a)}/diff/${enc(b)}`)).json();
  }
  async getChunk(app: string, hash: string, range?: { a: number; b: number }): Promise<ArrayBuffer> {
    return (await this.call("GET", `/v1/apps/${enc(app)}/chunks/${hash}`, undefined, undefined,
      range ? { range: `bytes=${range.a}-${range.b}` } : {})).arrayBuffer();
  }
  async getFile(app: string, slot: string, snap: string, path: string): Promise<ArrayBuffer> {
    return (await this.call("GET", `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots/${enc(snap)}/files/${segs(path)}`)).arrayBuffer();
  }
  async downloadArchive(app: string, slot: string, snap: string): Promise<ReadableStream<Uint8Array> | null> {
    return (await this.call("GET", `/v1/apps/${enc(app)}/slots/${enc(slot)}/snapshots/${enc(snap)}/archive.tar`)).body;
  }
  async listTokens(): Promise<unknown> { return (await this.call("GET", "/v1/tokens")).json(); }
  async createToken(name: string, scopes: string[]): Promise<unknown> {
    return (await this.call("POST", "/v1/tokens", JSON.stringify({ name, scopes }), "application/json")).json();
  }
  async getToken(id: string): Promise<unknown> {
    return (await this.call("GET", `/v1/tokens/${enc(id)}`)).json();
  }
  async patchToken(id: string, patch: Record<string, unknown>): Promise<unknown> {
    return (await this.call("PATCH", `/v1/tokens/${enc(id)}`, JSON.stringify(patch), "application/json")).json();
  }
  async revokeToken(id: string): Promise<void> {
    await this.call("DELETE", `/v1/tokens/${enc(id)}`);
  }
  async tokenEvents(id: string): Promise<unknown> {
    return (await this.call("GET", `/v1/tokens/${enc(id)}/events`)).json();
  }
  async tokenStats(id: string): Promise<unknown> {
    return (await this.call("GET", `/v1/tokens/${enc(id)}/stats`)).json();
  }
  async vaultGet(): Promise<unknown> { return (await this.call("GET", "/v1/vault")).json(); }
  async vaultPut(v: unknown): Promise<void> {
    await this.call("PUT", "/v1/vault", JSON.stringify(v), "application/json");
  }
  async vaultDelete(): Promise<void> { await this.call("DELETE", "/v1/vault"); }

  async *streamEvents(signal?: AbortSignal): AsyncIterable<SseEvent> {
    let lastId: string | undefined;
    let backoff = 500;
    for (;;) {
      const r = await this.call("GET", "/v1/events", undefined, undefined,
        { accept: "text/event-stream", ...(lastId ? { "last-event-id": lastId } : {}) }, signal);
      if (!r.body) break;
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      let buf = "", name = "", data = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done || signal?.aborted) break;
        buf += dec.decode(value, { stream: true });
        for (;;) {
          const i = buf.indexOf("\n");
          if (i < 0) break;
          const line = buf.slice(0, i).replace(/\r$/, "");
          buf = buf.slice(i + 1);
          if (line === "") {
            if (data) yield { id: lastId ?? "", name: name || "message", data };
            name = ""; data = "";
          } else if (line.startsWith("event:")) name = line.slice(6).trim();
          else if (line.startsWith("data:")) data = line.slice(5).trim();
          else if (line.startsWith("id:")) lastId = line.slice(3).trim();
        }
      }
      if (signal?.aborted) break;
      backoff = Math.min(backoff * 2, 10_000);
      await new Promise(r2 => setTimeout(r2, backoff + Math.random() * backoff / 4));
    }
  }
}
