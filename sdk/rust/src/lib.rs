// SPDX-License-Identifier: 0BSD

//! saves-sdk: blocking client for the saves save-sync HTTP API.
#![allow(clippy::result_large_err)]

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug)]
pub struct Error {
    pub status: u16,
    pub code: String,
    pub title: String,
    pub detail: String,
    pub request_id: String,
    pub retry_after: Option<u64>,
    pub head: Option<String>,
    pub transport: Option<String>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.title)
    }
}
impl std::error::Error for Error {}

fn err(status: u16, code: &str, title: &str) -> Error {
    Error {
        status,
        code: code.into(),
        title: title.into(),
        detail: String::new(),
        request_id: String::new(),
        retry_after: None,
        head: None,
        transport: None,
    }
}

pub struct Client {
    base: String,
    token: String,
    agent: ureq::Agent,
    retries: u32,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Client {
    pub fn new(base_url: &str, token: &str) -> Self {
        Client {
            base: base_url.trim_end_matches('/').into(),
            token: token.into(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
            retries: 3,
        }
    }
    pub fn timeout(mut self, d: Duration) -> Self {
        self.agent = ureq::AgentBuilder::new().timeout(d).build();
        self
    }
    pub fn retries(mut self, n: u32) -> Self {
        self.retries = n;
        self
    }
    pub fn user_agent(mut self, ua: &str) -> Self {
        self.agent = ureq::AgentBuilder::new()
            .user_agent(ua)
            .timeout(Duration::from_secs(30))
            .build();
        self
    }

    fn problem(resp: ureq::Response) -> Error {
        let status = resp.status();
        let rid = resp.header("X-Request-Id").unwrap_or("").to_string();
        let ra = resp.header("Retry-After").and_then(|s| s.parse().ok());
        let body = resp.into_string().unwrap_or_default();
        let mut e = err(status, "internal", "error");
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            e.code = v["code"].as_str().unwrap_or("internal").into();
            e.title = v["title"].as_str().unwrap_or("").into();
            e.detail = v["detail"].as_str().unwrap_or("").into();
            e.head = v["head"].as_str().map(String::from);
        }
        e.request_id = rid;
        e.retry_after = ra;
        e
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        ct: &str,
        extra: &[(&str, &str)],
    ) -> Result<ureq::Response, Error> {
        let idem = matches!(method, "GET" | "HEAD" | "DELETE")
            || (method == "PUT" && path.contains("/chunks/"));
        let mut attempt = 0u32;
        loop {
            let mut req = self
                .agent
                .request(method, &format!("{}{}", self.base, path))
                .set("Authorization", &format!("Bearer {}", self.token));
            for (k, v) in extra {
                req = req.set(k, v);
            }
            let res = match body.as_ref() {
                Some(b) => req.set("Content-Type", ct).send_bytes(b),
                None => req.call(),
            };
            match res {
                Ok(r) => return Ok(r),
                Err(ureq::Error::Status(_, r)) => {
                    let status = r.status();
                    let retryable = status == 429 || status == 503 || (idem && status >= 500);
                    if attempt < self.retries && retryable {
                        attempt += 1;
                        let wait = r
                            .header("Retry-After")
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(500 * attempt as u64)
                            .min(10_000);
                        std::thread::sleep(Duration::from_millis(wait));
                        continue;
                    }
                    return Err(Self::problem(r));
                }
                Err(ureq::Error::Transport(t)) => {
                    if attempt < self.retries && idem {
                        attempt += 1;
                        std::thread::sleep(Duration::from_millis(500 * attempt as u64));
                        continue;
                    }
                    return Err(err(0, "transport", &t.to_string()));
                }
            }
        }
    }

    fn json<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        ct: &str,
    ) -> Result<T, Error> {
        let r = self.call(method, path, body, ct, &[])?;
        r.into_json().map_err(|e| err(0, "parse", &e.to_string()))
    }

    pub fn me(&self) -> Result<serde_json::Value, Error> {
        self.json("GET", "/v1/me", None, "")
    }

    pub fn list_apps(&self) -> Result<Vec<serde_json::Value>, Error> {
        self.json("GET", "/v1/apps", None, "")
    }

    pub fn get_slot(&self, app: &str, slot: &str) -> Result<serde_json::Value, Error> {
        self.json(
            "GET",
            &format!("/v1/apps/{}/slots/{}", enc(app), enc(slot)),
            None,
            "",
        )
    }

    pub fn list_snapshots(&self, app: &str, slot: &str) -> Result<serde_json::Value, Error> {
        self.json(
            "GET",
            &format!("/v1/apps/{}/slots/{}/snapshots", enc(app), enc(slot)),
            None,
            "",
        )
    }

    pub fn get_manifest(&self, app: &str, slot: &str, id: &str) -> Result<Manifest, Error> {
        self.json(
            "GET",
            &format!(
                "/v1/apps/{}/slots/{}/snapshots/{}",
                enc(app),
                enc(slot),
                enc(id)
            ),
            None,
            "",
        )
    }

    fn begin2(
        &self,
        app: &str,
        slot: &str,
        hdr: &[(&str, &str)],
        m: &Manifest,
    ) -> Result<BeginOut, Error> {
        let b = serde_json::to_vec(m).map_err(|e| err(0, "ser", &e.to_string()))?;
        let r = self.call(
            "POST",
            &format!("/v1/apps/{}/slots/{}/snapshots", enc(app), enc(slot)),
            Some(b),
            "application/json",
            hdr,
        )?;
        r.into_json().map_err(|e| err(0, "parse", &e.to_string()))
    }

    pub fn put_chunk(
        &self,
        app: &str,
        slot: &str,
        snap: &str,
        hash: &str,
        data: &[u8],
    ) -> Result<(), Error> {
        self.call(
            "PUT",
            &format!(
                "/v1/apps/{}/slots/{}/snapshots/{}/chunks/{}",
                enc(app),
                enc(slot),
                enc(snap),
                hash
            ),
            Some(data.to_vec()),
            "application/octet-stream",
            &[],
        )?;
        Ok(())
    }

    pub fn commit_snapshot(
        &self,
        app: &str,
        slot: &str,
        id: &str,
        if_match: &str,
        force: bool,
    ) -> Result<serde_json::Value, Error> {
        let mut p = format!(
            "/v1/apps/{}/slots/{}/snapshots/{}/commit",
            enc(app),
            enc(slot),
            enc(id)
        );
        if force {
            p += "?force=1";
        }
        let hdr = [("If-Match", if_match)];
        let r = self.call("POST", &p, None, "", &hdr)?;
        r.into_json().map_err(|e| err(0, "parse", &e.to_string()))
    }

    pub fn delete_snapshot(&self, app: &str, slot: &str, id: &str) -> Result<(), Error> {
        self.call(
            "DELETE",
            &format!(
                "/v1/apps/{}/slots/{}/snapshots/{}",
                enc(app),
                enc(slot),
                enc(id)
            ),
            None,
            "",
            &[],
        )?;
        Ok(())
    }

    pub fn get_chunk(
        &self,
        app: &str,
        hash: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Vec<u8>, Error> {
        let mut hdr = vec![];
        let rg;
        if let Some((a, b)) = range {
            rg = format!("bytes={}-{}", a, b);
            hdr.push(("Range", rg.as_str()));
        }
        let r = self.call(
            "GET",
            &format!("/v1/apps/{}/chunks/{}", enc(app), hash),
            None,
            "",
            &hdr,
        )?;
        let mut out = Vec::new();
        r.into_reader()
            .read_to_end(&mut out)
            .map_err(|e| err(0, "io", &e.to_string()))?;
        Ok(out)
    }

    pub fn get_file(
        &self,
        app: &str,
        slot: &str,
        snap: &str,
        path: &str,
    ) -> Result<Vec<u8>, Error> {
        let r = self.call(
            "GET",
            &format!(
                "/v1/apps/{}/slots/{}/snapshots/{}/files/{}",
                enc(app),
                enc(slot),
                enc(snap),
                segs(path)
            ),
            None,
            "",
            &[],
        )?;
        let mut out = Vec::new();
        r.into_reader()
            .read_to_end(&mut out)
            .map_err(|e| err(0, "io", &e.to_string()))?;
        Ok(out)
    }

    pub fn download_archive<W: Write>(
        &self,
        app: &str,
        slot: &str,
        snap: &str,
        w: &mut W,
    ) -> Result<(), Error> {
        let r = self.call(
            "GET",
            &format!(
                "/v1/apps/{}/slots/{}/snapshots/{}/archive.tar",
                enc(app),
                enc(slot),
                enc(snap)
            ),
            None,
            "",
            &[],
        )?;
        std::io::copy(&mut r.into_reader(), w).map_err(|e| err(0, "io", &e.to_string()))?;
        Ok(())
    }

    pub fn list_tokens(&self) -> Result<Vec<serde_json::Value>, Error> {
        self.json("GET", "/v1/tokens", None, "")
    }
    pub fn create_token(&self, name: &str, scopes: &[&str]) -> Result<serde_json::Value, Error> {
        let b = serde_json::to_vec(&serde_json::json!({"name": name, "scopes": scopes})).unwrap();
        self.json("POST", "/v1/tokens", Some(b), "application/json")
    }
    pub fn get_token(&self, id: &str) -> Result<serde_json::Value, Error> {
        self.json("GET", &format!("/v1/tokens/{}", enc(id)), None, "")
    }
    pub fn patch_token(
        &self,
        id: &str,
        patch: &serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        let b = serde_json::to_vec(patch).unwrap();
        self.json(
            "PATCH",
            &format!("/v1/tokens/{}", enc(id)),
            Some(b),
            "application/json",
        )
    }
    pub fn revoke_token(&self, id: &str) -> Result<(), Error> {
        self.call("DELETE", &format!("/v1/tokens/{}", enc(id)), None, "", &[])?;
        Ok(())
    }
    pub fn token_events(&self, id: &str) -> Result<serde_json::Value, Error> {
        self.json("GET", &format!("/v1/tokens/{}/events", enc(id)), None, "")
    }
    pub fn token_stats(&self, id: &str) -> Result<serde_json::Value, Error> {
        self.json("GET", &format!("/v1/tokens/{}/stats", enc(id)), None, "")
    }
    pub fn vault_get(&self) -> Result<serde_json::Value, Error> {
        self.json("GET", "/v1/vault", None, "")
    }
    pub fn vault_put(&self, v: &serde_json::Value) -> Result<(), Error> {
        let b = serde_json::to_vec(v).unwrap();
        self.call("PUT", "/v1/vault", Some(b), "application/json", &[])?;
        Ok(())
    }
    pub fn vault_delete(&self) -> Result<(), Error> {
        self.call("DELETE", "/v1/vault", None, "", &[])?;
        Ok(())
    }

    // high level push and pull

    pub fn push(
        &self,
        app: &str,
        slot: &str,
        dir: &Path,
        opts: &PushOptions,
    ) -> Result<String, Error> {
        let me = self.me()?;
        let lim = &me["limits"];
        let inline_max = lim["inline_max_bytes"].as_u64().unwrap_or(64 * 1024);
        let cs = opts.chunk_size.clamp(
            lim["min_chunk_bytes"].as_u64().unwrap_or(256 * 1024),
            lim["max_chunk_bytes"].as_u64().unwrap_or(8 << 20),
        );
        let mut files: Vec<FileEntry> = Vec::new();
        let mut dirs: Vec<String> = Vec::new();
        walk(dir, Path::new(""), &mut files, &mut dirs, &opts.root)?;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut manifest_files = Vec::new();
        let mut chunks: Vec<(String, PathBuf, u64, u64)> = Vec::new();
        for f in &files {
            let mut e = File {
                path: f.path.clone(),
                size: f.size as i64,
                mode: f.mode,
                mtime_ns: f.mtime_ns,
                chunks: None,
                inline: None,
            };
            if f.size <= inline_max {
                e.inline =
                    Some(base64::engine::general_purpose::STANDARD.encode(
                        std::fs::read(&f.full).map_err(|e2| err(0, "io", &e2.to_string()))?,
                    ));
            } else {
                let data = std::fs::read(&f.full).map_err(|e2| err(0, "io", &e2.to_string()))?;
                let mut off = 0usize;
                let mut refs = Vec::new();
                while off < data.len() {
                    let end = (off + cs as usize).min(data.len());
                    let c = &data[off..end];
                    let h = hex_sha(c);
                    refs.push(ChunkRef {
                        h: h.clone(),
                        n: c.len() as u32,
                    });
                    chunks.push((h, f.full.clone(), off as u64, (end - off) as u64));
                    off = end;
                }
                e.chunks = Some(refs);
            }
            manifest_files.push(e);
        }
        let head = self
            .get_slot(app, slot)
            .ok()
            .and_then(|v| v["head"].as_str().map(String::from));
        let m = Manifest {
            version: 1,
            enc: None,
            parent: head.clone(),
            device: opts.device.clone(),
            label: opts.label.clone(),
            dirs: dirs.clone(),
            files: manifest_files,
        };
        let hdrs: Vec<(&str, &str)> = match &head {
            Some(h) => vec![("If-Match", h.as_str())],
            None => vec![],
        };
        let bo = self.begin2(app, slot, &hdrs, &m)?;
        // upload missing chunks
        for (h, file, off, len) in &chunks {
            if bo.missing.iter().any(|m| m == h) {
                let mut f2 =
                    std::fs::File::open(file).map_err(|e2| err(0, "io", &e2.to_string()))?;
                f2.seek(std::io::SeekFrom::Start(*off))
                    .map_err(|e2| err(0, "io", &e2.to_string()))?;
                let mut buf = vec![0u8; *len as usize];
                f2.read_exact(&mut buf)
                    .map_err(|e2| err(0, "io", &e2.to_string()))?;
                self.put_chunk(app, slot, &bo.id, h, &buf)?;
            }
        }
        let res =
            self.commit_snapshot(app, slot, &bo.id, head.as_deref().unwrap_or(""), opts.force)?;
        Ok(res["head"].as_str().unwrap_or(&bo.id).to_string())
    }

    pub fn pull(
        &self,
        app: &str,
        slot: &str,
        snap: &str,
        dir: &Path,
        _opts: &PullOptions,
    ) -> Result<(), Error> {
        let m = self.get_manifest(app, slot, snap)?;
        if m.enc.is_some() {
            return Err(err(409, "encrypted", "snapshot is encrypted"));
        }
        for f in &m.files {
            safe_path(&f.path)?;
            let dst = dir.join(&f.path);
            if let Some(p) = dst.parent() {
                std::fs::create_dir_all(p).map_err(|e| err(0, "io", &e.to_string()))?;
            }
            let data = if let Some(inl) = &f.inline {
                base64::engine::general_purpose::STANDARD
                    .decode(inl)
                    .map_err(|e| err(0, "b64", &e.to_string()))?
            } else {
                let mut out = Vec::new();
                for c in f.chunks.as_deref().unwrap_or(&[]) {
                    let b = self.get_chunk(app, &c.h, None)?;
                    if hex_sha(&b) != c.h {
                        return Err(err(0, "checksum", "chunk hash mismatch"));
                    }
                    out.extend_from_slice(&b);
                }
                out
            };
            if data.len() as i64 != f.size {
                return Err(err(0, "size", "size mismatch"));
            }
            let tmp = dst.with_extension("saves-tmp");
            std::fs::write(&tmp, &data).map_err(|e| err(0, "io", &e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &tmp,
                    std::fs::Permissions::from_mode((f.mode as u32) & 0o777),
                );
            }
            std::fs::rename(&tmp, &dst).map_err(|e| err(0, "io", &e.to_string()))?;
        }
        let mut seen = std::collections::HashSet::new();
        for f in &m.files { seen.insert(dir.join(&f.path)); }
        for d in &m.dirs {
            let p = dir.join(d);
            std::fs::create_dir_all(&p).map_err(|e| err(0, "io", &e.to_string()))?;
            seen.insert(p);
        }
        if _opts.prune {
            for e in walkdir_files(dir) {
                if !seen.contains(&e) { let _ = std::fs::remove_file(e); }
            }
        }
        Ok(())
    }
}

impl Client {
    /// Iterates SSE events from /v1/events, reconnecting with backoff.
    pub fn stream_events(&self) -> SseIter<'_> {
        SseIter { c: self, last_id: String::new(), buf: Vec::new(), wait_ms: 500 }
    }
}

/// One server-sent event.
pub struct SseEvent { pub id: String, pub name: String, pub data: String }

/// Blocking SSE iterator (fetch() call form).
pub struct SseIter<'a> {
    c: &'a Client,
    last_id: String,
    buf: Vec<SseEvent>,
    wait_ms: u64,
}

impl<'a> Iterator for SseIter<'a> {
    type Item = Result<SseEvent, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(e) = self.buf.pop() { return Some(Ok(e)); }
            let mut hdrs = vec![("Accept", "text/event-stream")];
            if !self.last_id.is_empty() { hdrs.push(("Last-Event-ID", self.last_id.as_str())); }
            match self.c.call("GET", "/v1/events", None, "", &hdrs) {
                Ok(r) => {
                    let text = r.into_string().unwrap_or_default();
                    self.wait_ms = 500;
                    let mut name = String::new();
                    let mut data = String::new();
                    let mut got = Vec::new();
                    for line in text.lines() {
                        if line.is_empty() {
                            if !data.is_empty() {
                                got.push(SseEvent { id: self.last_id.clone(), name: name.clone().replace(' ', ""), data: data.clone() });
                            }
                            name.clear(); data.clear();
                        } else if let Some(v) = line.strip_prefix("event:") { name = v.trim().to_string(); }
                        else if let Some(v) = line.strip_prefix("data:") { data = v.trim().to_string(); }
                        else if let Some(v) = line.strip_prefix("id:") { self.last_id = v.trim().to_string(); }
                    }
                    self.buf = got.into_iter().rev().collect();
                }
                Err(_) => {
                    let jitter = (self.wait_ms as f64 * 0.25 * rand_frac()) as u64;
                    std::thread::sleep(Duration::from_millis(self.wait_ms + jitter));
                    self.wait_ms = (self.wait_ms * 2).min(10_000);
                }
            }
        }
    }
}

fn rand_frac() -> f64 {
    use std::time::SystemTime;
    let n = SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    (n % 1000) as f64 / 1000.0
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect()
}

fn segs(p: &str) -> String {
    p.split('/').map(enc).collect::<Vec<_>>().join("/")
}

fn hex_sha(b: &[u8]) -> String {
    let d = Sha256::digest(b);
    let mut s = String::with_capacity(64);
    for byte in d {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Checks a manifest path is safe to write.
pub fn safe_path_public(p: &str) -> Result<(), Error> {
    safe_path(p)
}

fn walkdir_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&p) {
            for e in rd.flatten() {
                let ep = e.path();
                if ep.is_dir() { stack.push(ep); } else { out.push(ep); }
            }
        }
    }
    out
}

fn safe_path(p: &str) -> Result<(), Error> {
    if p.starts_with('/')
        || p.contains('\\')
        || p.split('/').any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(err(400, "bad_path", "unsafe path"));
    }
    Ok(())
}

struct FileEntry {
    path: String,
    full: PathBuf,
    size: u64,
    mode: i64,
    mtime_ns: i64,
}

fn walk(
    base: &Path,
    rel: &Path,
    files: &mut Vec<FileEntry>,
    dirs: &mut Vec<String>,
    root: &str,
) -> Result<(), Error> {
    let p = if rel.as_os_str().is_empty() {
        base.to_path_buf()
    } else {
        base.join(rel)
    };
    let mut ents: Vec<_> = std::fs::read_dir(&p)
        .map_err(|e| err(0, "io", &e.to_string()))?
        .filter_map(|e| e.ok())
        .collect();
    ents.sort_by_key(|e| e.file_name());
    for e in ents {
        let name = e.file_name().to_string_lossy().to_string();
        let rp = if rel.as_os_str().is_empty() {
            name.clone()
        } else {
            format!("{}/{}", rel.display(), name)
        };
        let full = p.join(&name);
        let md = e.metadata().map_err(|e2| err(0, "io", &e2.to_string()))?;
        if md.is_symlink() {
            continue;
        }
        let joined = format!("{}/{}", root, rp);
        if md.is_dir() {
            dirs.push(joined);
            walk(base, &PathBuf::from(rp), files, dirs, root)?;
        } else {
            let mode = unix_mode(&md);
            let mt = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            files.push(FileEntry {
                path: joined,
                full,
                size: md.len(),
                mode,
                mtime_ns: mt,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_mode(md: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    (md.mode() & 0o777) as i64
}
#[cfg(not(unix))]
fn unix_mode(_: &std::fs::Metadata) -> i64 {
    0o644
}

#[derive(Default)]
pub struct PushOptions {
    pub root: String,
    pub label: String,
    pub device: String,
    pub force: bool,
    pub chunk_size: u64,
    pub parallelism: usize,
    pub on_progress: Option<Box<dyn Fn(u64, u64)>>,
}

#[derive(Default)]
pub struct PullOptions {
    pub prune: bool,
    pub on_progress: Option<Box<dyn Fn(u64, u64)>>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct ChunkRef {
    pub h: String,
    pub n: u32,
}

#[derive(Serialize, Deserialize, Default)]
pub struct File {
    pub path: String,
    pub size: i64,
    #[serde(default)]
    pub mode: i64,
    #[serde(default)]
    pub mtime_ns: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunks: Option<Vec<ChunkRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Manifest {
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub dirs: Vec<String>,
    pub files: Vec<File>,
}

#[derive(Deserialize)]
pub struct BeginOut {
    pub id: String,
    #[serde(default)]
    pub missing: Vec<String>,
}
