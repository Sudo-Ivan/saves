// SPDX-License-Identifier: 0BSD

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Saves.Sdk;

/// <summary>Error thrown on saves API failures.</summary>
public sealed class SavesException : Exception
{
    public int Status { get; set; }
    public string Code { get; set; } = "";
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public string RequestId { get; set; } = "";
    public TimeSpan? RetryAfter { get; set; }
    public string? Head { get; set; }
    public SavesException(string message) : base(message) { }
}

/// <summary>Client options.</summary>
public sealed class SavesClientOptions
{
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public int Retries { get; set; } = 3;
    public string? UserAgent { get; set; }
    public HttpMessageHandler? Handler { get; set; }
}

/// <summary>Transfer progress callback data.</summary>
public readonly record struct TransferProgress(long Done, long Total);

/// <summary>Server-sent event.</summary>
public readonly record struct SseEvent(string Id, string Name, string Data);

/// <summary>Push options.</summary>
public sealed class PushOptions
{
    public string Root { get; set; } = "save";
    public string Label { get; set; } = "";
    public string Device { get; set; } = "";
    public bool Force { get; set; }
    public int ChunkSize { get; set; } = 1 << 20;
    public int Parallelism { get; set; } = 4;
    public IProgress<TransferProgress>? Progress { get; set; }
}

/// <summary>Pull options.</summary>
public sealed class PullOptions
{
    public bool Prune { get; set; }
    public IProgress<TransferProgress>? Progress { get; set; }
}

public sealed record Slot([property: JsonPropertyName("slot")] string SlotName,
    [property: JsonPropertyName("head")] string Head);
public sealed record Snapshot([property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("device")] string? Device,
    [property: JsonPropertyName("enc")] bool Enc);
public sealed record TokenStats(
    [property: JsonPropertyName("total_requests")] long TotalRequests,
    [property: JsonPropertyName("requests_24h")] long Requests24h,
    [property: JsonPropertyName("requests_30d")] long Requests30d);

public sealed record Manifest(
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("files")] List<ManifestFile> Files)
{
    [JsonPropertyName("enc")] public JsonElement? Enc { get; init; }
    [JsonPropertyName("parent")] public string? Parent { get; init; }
    [JsonPropertyName("device")] public string? Device { get; init; }
    [JsonPropertyName("label")] public string? Label { get; init; }
    [JsonPropertyName("dirs")] public List<string>? Dirs { get; init; }
}

public sealed record ManifestFile(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("mode")] int Mode,
    [property: JsonPropertyName("mtime_ns")] long MtimeNs,
    [property: JsonPropertyName("chunks")] List<ChunkRef>? Chunks,
    [property: JsonPropertyName("inline")] string? Inline);

public sealed record ChunkRef(
    [property: JsonPropertyName("h")] string H,
    [property: JsonPropertyName("n")] int N);

public sealed record BeginOut(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("missing")] List<string> Missing);

/// <summary>Blocking-capable client for the saves API.</summary>
public sealed class SavesClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly int _retries;
    private readonly string _base;

    public SavesClient(Uri baseUrl, string token, SavesClientOptions? options = null)
    {
        var o = options ?? new SavesClientOptions();
        _base = baseUrl.AbsoluteUri.TrimEnd('/');
        _http = o.Handler != null ? new HttpClient(o.Handler) : new HttpClient();
        _http.Timeout = o.Timeout;
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (o.UserAgent != null)
            _http.DefaultRequestHeaders.UserAgent.ParseAdd(o.UserAgent);
        _retries = o.Retries;
    }

    public void Dispose() => _http.Dispose();

    public override string ToString() => $"SavesClient({_base})";

    private static bool Idempotent(HttpMethod m, string path) =>
        m == HttpMethod.Get || m == HttpMethod.Head || m == HttpMethod.Delete ||
        (m == HttpMethod.Put && path.Contains("/chunks/"));

    private static SavesException ToProblem(HttpResponseMessage r, string body)
    {
        var e = new SavesException($"HTTP {(int)r.StatusCode}")
        {
            Status = (int)r.StatusCode,
            Code = "internal",
            Title = r.ReasonPhrase ?? "",
            RequestId = r.Headers.TryGetValues("X-Request-Id", out var v) ? string.Join("", v) : "",
            RetryAfter = r.Headers.RetryAfter?.Delta,
        };
        try
        {
            using var doc = JsonDocument.Parse(body);
            var p = doc.RootElement;
            e.Code = p.TryGetProperty("code", out var c) ? c.GetString() ?? e.Code : e.Code;
            e.Title = p.TryGetProperty("title", out var t) ? t.GetString() ?? e.Title : e.Title;
            e.Detail = p.TryGetProperty("detail", out var d) ? d.GetString() ?? "" : "";
            e.Head = p.TryGetProperty("head", out var h) ? h.GetString() : null;
        }
        catch (JsonException) { }
        return e;
    }

    private async Task<HttpResponseMessage> Send(HttpMethod method, string path,
        HttpContent? body, CancellationToken ct, params (string K, string V)[] hdrs)
    {
        var idem = Idempotent(method, path);
        for (var attempt = 0; ; attempt++)
        {
            using var req = new HttpRequestMessage(method, _base + path);
            req.Content = body;
            foreach (var (k, v) in hdrs) req.Headers.TryAddWithoutValidation(k, v);
            HttpResponseMessage r;
            try
            {
                r = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (idem && attempt < _retries)
            {
                await Task.Delay(500 * (attempt + 1), ct).ConfigureAwait(false);
                continue;
            }
            var retryable = r.StatusCode == (HttpStatusCode)429 || r.StatusCode == HttpStatusCode.ServiceUnavailable ||
                            (idem && (int)r.StatusCode >= 500);
            if (attempt < _retries && retryable)
            {
                var wait = r.Headers.RetryAfter?.Delta ?? TimeSpan.FromMilliseconds(Math.Min(500 * (attempt + 1), 10_000));
                r.Dispose();
                await Task.Delay(wait, ct).ConfigureAwait(false);
                continue;
            }
            if (r.IsSuccessStatusCode) return r;
            var text = await r.Content.ReadAsStringAsync().ConfigureAwait(false);
            r.Dispose();
            throw ToProblem(r, text);
        }
    }

    private async Task<T> Json<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        var content = body == null ? null
            : new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        var r = await Send(method, path, content, ct).ConfigureAwait(false);
        using var s = await r.Content.ReadAsStreamAsync().ConfigureAwait(false);
        return (await JsonSerializer.DeserializeAsync<T>(s, cancellationToken: ct).ConfigureAwait(false))!;
    }

    public Task<JsonDocument> MeAsync(CancellationToken ct = default) => Json<JsonDocument>(HttpMethod.Get, "/v1/me", null, ct);
    public Task<JsonDocument> ListAppsAsync(CancellationToken ct = default) => Json<JsonDocument>(HttpMethod.Get, "/v1/apps", null, ct);
    public Task<JsonDocument> GetSlotAsync(string app, string slot, CancellationToken ct = default) =>
        Json<JsonDocument>(HttpMethod.Get, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}", null, ct);
    public Task<JsonDocument> ListSnapshotsAsync(string app, string slot, CancellationToken ct = default) =>
        Json<JsonDocument>(HttpMethod.Get, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots", null, ct);
    public Task<Manifest> GetManifestAsync(string app, string slot, string id, CancellationToken ct = default) =>
        Json<Manifest>(HttpMethod.Get, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots/{Esc(id)}", null, ct);
    public async Task<BeginOut> BeginSnapshotAsync(string app, string slot, string? ifMatch, Manifest m, CancellationToken ct = default)
    {
        var content = new StringContent(JsonSerializer.Serialize(m), Encoding.UTF8, "application/json");
        var r = ifMatch != null
            ? await Send(HttpMethod.Post, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots", content, ct, ("If-Match", ifMatch)).ConfigureAwait(false)
            : await Send(HttpMethod.Post, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots", content, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<BeginOut>(await r.Content.ReadAsStringAsync().ConfigureAwait(false))!;
    }
    public async Task PutChunkAsync(string app, string slot, string snap, string hash, byte[] data, CancellationToken ct = default)
    {
        var content = new ByteArrayContent(data);
        var r = await Send(HttpMethod.Put, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots/{Esc(snap)}/chunks/{hash}", content, ct).ConfigureAwait(false);
        r.Dispose();
    }
    public async Task<JsonDocument> CommitSnapshotAsync(string app, string slot, string id, string? ifMatch, bool force, CancellationToken ct = default)
    {
        var p = $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots/{Esc(id)}/commit" + (force ? "?force=1" : "");
        var r = ifMatch != null
            ? await Send(HttpMethod.Post, p, null, ct, ("If-Match", ifMatch)).ConfigureAwait(false)
            : await Send(HttpMethod.Post, p, null, ct).ConfigureAwait(false);
        return JsonDocument.Parse(await r.Content.ReadAsStringAsync().ConfigureAwait(false));
    }
    public async Task DeleteSnapshotAsync(string app, string slot, string id, CancellationToken ct = default)
    {
        var r = await Send(HttpMethod.Delete, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots/{Esc(id)}", null, ct).ConfigureAwait(false);
        r.Dispose();
    }
    public async Task<JsonDocument> DiffAsync(string app, string slot, string a, string b, CancellationToken ct = default)
    {
        var r = await Send(HttpMethod.Get, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots/{Esc(a)}/diff/{Esc(b)}", null, ct).ConfigureAwait(false);
        return JsonDocument.Parse(await r.Content.ReadAsStringAsync().ConfigureAwait(false));
    }
    public async Task<byte[]> GetChunkAsync(string app, string hash, (long A, long B)? range = null, CancellationToken ct = default)
    {
        var r = range.HasValue
            ? await Send(HttpMethod.Get, $"/v1/apps/{Esc(app)}/chunks/{hash}", null, ct, ("Range", $"bytes={range.Value.A}-{range.Value.B}")).ConfigureAwait(false)
            : await Send(HttpMethod.Get, $"/v1/apps/{Esc(app)}/chunks/{hash}", null, ct).ConfigureAwait(false);
        return await r.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }
    public async Task<byte[]> GetFileAsync(string app, string slot, string snap, string path, CancellationToken ct = default)
    {
        var r = await Send(HttpMethod.Get, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots/{Esc(snap)}/files/{EscSegs(path)}", null, ct).ConfigureAwait(false);
        return await r.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }
    public async Task DownloadArchiveAsync(string app, string slot, string snap, Stream w, CancellationToken ct = default)
    {
        var r = await Send(HttpMethod.Get, $"/v1/apps/{Esc(app)}/slots/{Esc(slot)}/snapshots/{Esc(snap)}/archive.tar", null, ct).ConfigureAwait(false);
        await r.Content.CopyToAsync(w).ConfigureAwait(false);
    }
    public Task<JsonDocument> ListTokensAsync(CancellationToken ct = default) => Json<JsonDocument>(HttpMethod.Get, "/v1/tokens", null, ct);
    public async Task<JsonDocument> CreateTokenAsync(string name, string[] scopes, CancellationToken ct = default)
    {
        var r = await Send(HttpMethod.Post, "/v1/tokens",
            new StringContent(JsonSerializer.Serialize(new { name, scopes }), Encoding.UTF8, "application/json"), ct).ConfigureAwait(false);
        return JsonDocument.Parse(await r.Content.ReadAsStringAsync().ConfigureAwait(false));
    }
    public Task<JsonDocument> GetTokenAsync(string id, CancellationToken ct = default) => Json<JsonDocument>(HttpMethod.Get, $"/v1/tokens/{Esc(id)}", null, ct);
    public async Task<JsonDocument> PatchTokenAsync(string id, object patch, CancellationToken ct = default)
    {
        var r = await Send(new HttpMethod("PATCH"), $"/v1/tokens/{Esc(id)}",
            new StringContent(JsonSerializer.Serialize(patch), Encoding.UTF8, "application/json"), ct).ConfigureAwait(false);
        return JsonDocument.Parse(await r.Content.ReadAsStringAsync().ConfigureAwait(false));
    }
    public async Task RevokeTokenAsync(string id, CancellationToken ct = default)
    {
        var r = await Send(HttpMethod.Delete, $"/v1/tokens/{Esc(id)}", null, ct).ConfigureAwait(false);
        r.Dispose();
    }
    public Task<JsonDocument> TokenEventsAsync(string id, CancellationToken ct = default) => Json<JsonDocument>(HttpMethod.Get, $"/v1/tokens/{Esc(id)}/events", null, ct);
    public Task<JsonDocument> TokenStatsAsync(string id, CancellationToken ct = default) => Json<JsonDocument>(HttpMethod.Get, $"/v1/tokens/{Esc(id)}/stats", null, ct);
    public Task<JsonDocument> VaultGetAsync(CancellationToken ct = default) => Json<JsonDocument>(HttpMethod.Get, "/v1/vault", null, ct);
    public async Task VaultPutAsync(object v, CancellationToken ct = default)
    {
        var r = await Send(HttpMethod.Put, "/v1/vault",
            new StringContent(JsonSerializer.Serialize(v), Encoding.UTF8, "application/json"), ct).ConfigureAwait(false);
        r.Dispose();
    }
    public async Task VaultDeleteAsync(CancellationToken ct = default)
    {
        var r = await Send(HttpMethod.Delete, "/v1/vault", null, ct).ConfigureAwait(false);
        r.Dispose();
    }

    public async IAsyncEnumerable<SseEvent> StreamEventsAsync(string? lastId = null, [EnumeratorCancellation] CancellationToken ct = default)
    {
        var id = lastId;
        var wait = 500;
        int jitter() => (int)(new Random().NextDouble() * wait / 4);
        while (!ct.IsCancellationRequested)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, _base + "/v1/events");
            req.Headers.Accept.ParseAdd("text/event-stream");
            if (id != null) req.Headers.TryAddWithoutValidation("Last-Event-ID", id);
            HttpResponseMessage r;
            try { r = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false); }
            catch { await Task.Delay(wait + jitter(), ct).ConfigureAwait(false); wait = Math.Min(wait * 2, 10_000); continue; }
            if (!r.IsSuccessStatusCode) { r.Dispose(); await Task.Delay(wait + jitter(), ct).ConfigureAwait(false); wait = Math.Min(wait * 2, 10_000); continue; }
            wait = 500;
            var reader = new StreamReader(await r.Content.ReadAsStreamAsync().ConfigureAwait(false));
            string? name = null;
            var data = new StringBuilder();
            while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line && !ct.IsCancellationRequested)
            {
                if (line == "")
                {
                    if (data.Length > 0)
                        yield return new SseEvent(id ?? "", name ?? "message", data.ToString());
                    name = null; data.Clear();
                }
                else if (line.StartsWith("event:")) name = line.Substring(6).Trim();
                else if (line.StartsWith("data:")) data.Append(line.Substring(5).Trim());
                else if (line.StartsWith("id:")) id = line.Substring(3).Trim();
            }
        }
    }

    // high level

    private static string HexSha(byte[] b)
    {
        byte[] d;
        using (var h = System.Security.Cryptography.SHA256.Create()) d = h.ComputeHash(b);
        var s = new StringBuilder(64);
        foreach (var x in d) s.Append(x.ToString("x2"));
        return s.ToString();
    }

    private static string Esc(string s) => Uri.EscapeDataString(s);
    private static string EscSegs(string p) => string.Join("/", p.Split('/').Select(Esc));

    private static void SafePath(string p)
    {
        if (p.StartsWith("/") || p.Contains('\\') || p.Split('/').Any(s => s is "" or "." or ".."))
            throw new SavesException("unsafe path") { Status = 400, Code = "bad_path" };
    }

    public async Task<string> PushAsync(string app, string slot, string directory, PushOptions? options = null, CancellationToken ct = default)
    {
        var o = options ?? new PushOptions();
        var me = await MeAsync(ct).ConfigureAwait(false);
        var lim = me.RootElement.GetProperty("limits");
        var inlineMax = lim.GetProperty("inline_max_bytes").GetInt64();
        var cs = Clamp(o.ChunkSize, lim.GetProperty("min_chunk_bytes").GetInt64(), lim.GetProperty("max_chunk_bytes").GetInt64());

        var files = new List<(string Rel, string Full, long Size, int Mode, long MtimeNs)>();
        var dirs = new List<string>();
        Walk(new DirectoryInfo(directory), o.Root, files, dirs);
        files.Sort((a, b) => string.CompareOrdinal(a.Rel, b.Rel));

        var mfiles = new List<ManifestFile>();
        var chunks = new List<(string Hash, string File, long Off, int Len)>();
        long total = 0;
        foreach (var f in files)
        {
            total += f.Size;
            if (f.Size <= inlineMax)
            {
                mfiles.Add(new ManifestFile(f.Rel, f.Size, f.Mode, f.MtimeNs, null,
                    Convert.ToBase64String(File.ReadAllBytes(f.Full))));
            }
            else
            {
                var refs = new List<ChunkRef>();
                var data = File.ReadAllBytes(f.Full);
                for (var off = 0; off < data.Length; off += (int)cs)
                {
                    var len = (int)Math.Min(cs, data.Length - off);
                    var hh2 = HexSha(Slice(data, off, len));
                    refs.Add(new ChunkRef(hh2, len));
                    chunks.Add((hh2, f.Full, off, len));
                }
                mfiles.Add(new ManifestFile(f.Rel, f.Size, f.Mode, f.MtimeNs, refs, null));
            }
        }
        string? head = null;
        try { head = (await GetSlotAsync(app, slot, ct).ConfigureAwait(false)).RootElement.TryGetProperty("head", out var hh) ? hh.GetString() : null; }
        catch (SavesException e) when (e.Status == 404) { }
        var manifest = new Manifest(1, mfiles) { Device = o.Device, Label = o.Label, Parent = head, Dirs = dirs.Count > 0 ? dirs : null };
        var bo = await BeginSnapshotAsync(app, slot, head, manifest, ct).ConfigureAwait(false);
        var sem = new SemaphoreSlim(o.Parallelism);
        long done = 0;
        var tasks = chunks.Where(c => bo.Missing.Contains(c.Hash)).Select(async c =>
        {
            await sem.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var buf = new byte[c.Len];
                using var fs = File.OpenRead(c.File);
                fs.Seek(c.Off, SeekOrigin.Begin);
#if NET8_0_OR_GREATER
                await fs.ReadExactlyAsync(buf, ct).ConfigureAwait(false);
#else
                await fs.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
#endif
                await PutChunkAsync(app, slot, bo.Id, c.Hash, buf, ct).ConfigureAwait(false);
                var d = Interlocked.Add(ref done, c.Len);
                o.Progress?.Report(new TransferProgress(d, total));
            }
            finally { sem.Release(); }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
        var res = await CommitSnapshotAsync(app, slot, bo.Id, head, o.Force, ct).ConfigureAwait(false);
        return res.RootElement.TryGetProperty("head", out var h) ? h.GetString() ?? bo.Id : bo.Id;
    }

    public async Task PullAsync(string app, string slot, string snapId, string directory, PullOptions? options = null, CancellationToken ct = default)
    {
        var o = options ?? new PullOptions();
        var m = await GetManifestAsync(app, slot, snapId, ct).ConfigureAwait(false);
        if (m.Enc.HasValue) throw new SavesException("encrypted") { Status = 409, Code = "encrypted" };
        var seen = new HashSet<string>();
        foreach (var f in m.Files)
        {
            SafePath(f.Path);
            var dst = Path.Combine(directory, f.Path.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
            byte[] data;
            if (f.Inline != null)
                data = Convert.FromBase64String(f.Inline);
            else
            {
                var chs = f.Chunks ?? [];
                var parts = new byte[chs.Count][];
                var sem = new SemaphoreSlim(4);
                var tasks = chs.Select(async (c, i) =>
                {
                    await sem.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        var b = await GetChunkAsync(app, c.H, null, ct).ConfigureAwait(false);
                        if (HexSha(b) != c.H) throw new SavesException("checksum") { Status = 0, Code = "checksum" };
                        parts[i] = b;
                    }
                    finally { sem.Release(); }
                });
                await Task.WhenAll(tasks).ConfigureAwait(false);
                using var ms = new MemoryStream();
                foreach (var p in parts) ms.Write(p, 0, p.Length);
                data = ms.ToArray();
            }
            var tmp = dst + ".saves-tmp";
#if NET8_0_OR_GREATER
            await File.WriteAllBytesAsync(tmp, data, ct).ConfigureAwait(false);
            try { File.SetUnixFileMode(tmp, (UnixFileMode)(f.Mode & 0x1FF)); } catch { }
            File.Move(tmp, dst, true);
#else
            File.WriteAllBytes(tmp, data);
            if (File.Exists(dst)) File.Delete(dst);
            File.Move(tmp, dst);
#endif
            try { File.SetLastWriteTimeUtc(dst, DateTimeOffset.FromUnixTimeMilliseconds(f.MtimeNs / 1_000_000).UtcDateTime); } catch { }
            seen.Add(dst);
        }
        foreach (var d in m.Dirs ?? [])
        {
            var p = Path.Combine(directory, d.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(p);
            seen.Add(p);
        }
        if (o.Prune)
            foreach (var f in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
                if (!seen.Contains(f)) File.Delete(f);
    }

    private static byte[] Slice(byte[] a, int off, int len)
    {
        var o = new byte[len];
        Array.Copy(a, off, o, 0, len);
        return o;
    }

    private static long Clamp(long v, long lo, long hi) => v < lo ? lo : v > hi ? hi : v;

    private static void Walk(DirectoryInfo d, string root, List<(string Rel, string Full, long Size, int Mode, long MtimeNs)> files, List<string> dirs)
    {
        foreach (var e in d.EnumerateFileSystemInfos())
        {
            var rel = root + "/" + e.Name;
            if (e is DirectoryInfo sub)
            {
                dirs.Add(rel);
                Walk(sub, rel, files, dirs);
            }
            else if (e is FileInfo f)
            {
                var mode = 0;
#if NET8_0_OR_GREATER
                try { mode = (int)(f.UnixFileMode == default ? UnixFileMode.UserRead | UnixFileMode.UserWrite : f.UnixFileMode); } catch { }
#endif
                files.Add((rel, f.FullName, f.Length, mode, new DateTimeOffset(f.LastWriteTimeUtc).ToUnixTimeMilliseconds() * 1_000_000));
            }
        }
    }
}
