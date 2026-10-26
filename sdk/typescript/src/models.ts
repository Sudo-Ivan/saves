// SPDX-License-Identifier: 0BSD

export interface ChunkRef { h: string; n: number }
export interface FileEntry {
  path: string; size: number; mode: number; mtime_ns: number;
  chunks?: ChunkRef[]; inline?: string;
}
export interface Manifest {
  version: number; device?: string; label?: string; parent?: string;
  enc?: unknown; dirs?: string[]; files: FileEntry[];
}
export interface BeginOut { id: string; missing?: string[]; expires_at?: string }
export interface Slot { slot: string; head: string; created_at?: string }
export interface Snapshot { id: string; app: string; slot: string; label?: string; enc?: boolean }
export interface Token {
  id: string; user_id?: string; name: string; scopes: string[]; apps?: string[];
  allowed_cidrs?: string[];
}
export interface TokenCreate { name: string; scopes: string[]; apps?: string[]; expires_in?: string }
export interface SseEvent { id: string; name: string; data: string }
export interface ClientOptions {
  baseUrl: string;
  token: string;
  timeoutMs?: number;
  retries?: number;
  userAgent?: string;
  fetch?: typeof globalThis.fetch;
}

export interface Me {
  user: { id: string; subject?: string };
  tier?: string;
  scopes?: string[];
  anonymous?: boolean;
  require_encryption?: boolean;
  limits?: Record<string, number>;
  tier_limits?: Record<string, number>;
  bandwidth?: Record<string, unknown>;
}
export interface TokenStats {
  total_requests?: number;
  requests_24h?: number;
  requests_30d?: number;
}
export interface AppSummary { app: string; slots?: number; snapshots?: number; bytes?: number }
