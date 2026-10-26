# SPDX-License-Identifier: 0BSD
"""Blocking client for the saves API."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Generator, List, Optional, Tuple

from .errors import SavesError
from .models import BeginOut, ChunkRef, FileEntry, Manifest

_IDEMPOTENT = frozenset({"GET", "HEAD", "DELETE"})


def _enc(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _segs(p: str) -> str:
    return "/".join(_enc(seg) for seg in p.split("/"))


class SavesClient:
    """Blocking client for the saves API. Thread safe."""

    def __init__(self, base_url: str, token: str, timeout: int = 30,
                 retries: int = 3, user_agent: Optional[str] = None) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._retries = retries
        self._ua = user_agent or "saves-sdk-py"

    def __repr__(self) -> str:
        return f"SavesClient({self._base})"

    @staticmethod
    def _idem(method: str, path: str) -> bool:
        return method in _IDEMPOTENT or (method == "PUT" and "/chunks/" in path)

    def _problem(self, status: int, headers: Any, body: bytes) -> SavesError:
        e = SavesError(f"HTTP {status}")
        e.status = status
        e.request_id = headers.get("x-request-id", "")
        ra = headers.get("retry-after")
        if ra and ra.isdigit():
            e.retry_after = int(ra)
        try:
            v = json.loads(body)
            e.code = v.get("code", "internal")
            e.title = v.get("title", "")
            e.detail = v.get("detail", "")
            if isinstance(v.get("head"), str):
                e.head = v["head"]
        except Exception:
            pass
        return e

    def _call(self, method: str, path: str, body: Optional[bytes] = None,
              ctype: str = "", headers: Optional[Dict[str, str]] = None) -> Tuple[int, Any, bytes]:
        idem = self._idem(method, path)
        attempt = 0
        while True:
            req = urllib.request.Request(
                self._base + path, data=body, method=method,
                headers={"Authorization": f"Bearer {self._token}",
                         "User-Agent": self._ua, **(headers or {}),
                         **({"Content-Type": ctype} if ctype else {})})
            try:
                resp = urllib.request.urlopen(req, timeout=self._timeout)
                status, hdrs, data = resp.status, resp.headers, resp.read()
            except urllib.error.HTTPError as he:
                status, hdrs, data = he.code, he.headers, he.read()
            except (urllib.error.URLError, OSError) as te:
                if idem and attempt < self._retries:
                    attempt += 1
                    time.sleep(min(0.5 * attempt, 10))
                    continue
                e = SavesError(str(te))
                e.code = "transport"
                raise e
            if status < 400:
                return status, hdrs, data
            retryable = status in (429, 503) or (idem and status >= 500)
            if attempt < self._retries and retryable:
                attempt += 1
                ra = hdrs.get("retry-after")
                wait = int(ra) if ra and ra.isdigit() else min(0.5 * attempt, 10)
                time.sleep(wait)
                continue
            raise self._problem(status, hdrs, data)

    def _json(self, method: str, path: str, body: Optional[bytes] = None) -> Any:
        _, _, data = self._call(method, path, body, "application/json")
        return json.loads(data)

    def _enc_body(self, obj: Any) -> bytes:
        return json.dumps(obj).encode()

    # identity
    def me(self) -> Dict[str, Any]:
        return self._json("GET", "/v1/me")

    def register(self, invite: Optional[str] = None) -> Dict[str, Any]:
        return self._json("POST", "/v1/register", self._enc_body({"invite": invite}))

    # apps and slots
    def list_apps(self) -> Any:
        return self._json("GET", "/v1/apps")

    def list_slots(self, app: str) -> Any:
        return self._json("GET", f"/v1/apps/{_enc(app)}/slots")

    def get_slot(self, app: str, slot: str) -> Dict[str, Any]:
        return self._json("GET", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}")

    def delete_slot(self, app: str, slot: str) -> None:
        self._call("DELETE", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}")

    # snapshots
    def list_snapshots(self, app: str, slot: str) -> Any:
        return self._json("GET", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots")

    def get_manifest(self, app: str, slot: str, snap: str) -> Manifest:
        v = self._json("GET", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots/{_enc(snap)}")
        m = Manifest(
            device=v.get("device", ""), label=v.get("label", ""),
            parent=v.get("parent"), enc=v.get("enc"),
            dirs=v.get("dirs") or [])
        for f in v.get("files", []):
            fe = FileEntry(
                path=f["path"], size=f.get("size", 0),
                mode=f.get("mode", 0), mtime_ns=f.get("mtime_ns", 0),
                inline=f.get("inline"))
            fe.chunks = [ChunkRef(h=c["h"], n=c["n"]) for c in f.get("chunks", [])]
            m.files.append(fe)
        return m

    def begin_snapshot(self, app: str, slot: str, if_match: Optional[str],
                       manifest: Manifest) -> BeginOut:
        v: Dict[str, Any] = {"version": 1, "files": []}
        if manifest.device:
            v["device"] = manifest.device
        if manifest.label:
            v["label"] = manifest.label
        if manifest.parent:
            v["parent"] = manifest.parent
        if manifest.dirs:
            v["dirs"] = manifest.dirs
        for f in manifest.files:
            fj: Dict[str, Any] = {"path": f.path, "size": f.size,
                                  "mode": f.mode, "mtime_ns": f.mtime_ns}
            if f.inline is not None:
                fj["inline"] = f.inline
            else:
                fj["chunks"] = [{"h": c.h, "n": c.n} for c in f.chunks or []]
            v["files"].append(fj)
        hdrs = {"If-Match": if_match} if if_match else {}
        _, _, data = self._call("POST", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots",
                                self._enc_body(v), "application/json", hdrs)
        out = json.loads(data)
        return BeginOut(id=out["id"], missing=out.get("missing", []))

    def put_chunk(self, app: str, slot: str, snap: str, hash: str, data: bytes) -> None:
        self._call("PUT", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots/{_enc(snap)}/chunks/{hash}",
                   data, "application/octet-stream")

    def commit_snapshot(self, app: str, slot: str, snap: str,
                        if_match: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
        p = f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots/{_enc(snap)}/commit"
        if force:
            p += "?force=1"
        hdrs = {"If-Match": if_match} if if_match else {}
        _, _, data = self._call("POST", p, None, "", hdrs)
        return json.loads(data)

    def delete_snapshot(self, app: str, slot: str, snap: str) -> None:
        self._call("DELETE", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots/{_enc(snap)}")

    def diff(self, app: str, slot: str, a: str, b: str) -> Any:
        return self._json("GET", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots/{_enc(a)}/diff/{_enc(b)}")

    # reads
    def get_chunk(self, app: str, hash: str,
                  byte_range: Optional[Tuple[int, int]] = None) -> bytes:
        hdrs = {"Range": f"bytes={byte_range[0]}-{byte_range[1]}"} if byte_range else {}
        _, _, data = self._call("GET", f"/v1/apps/{_enc(app)}/chunks/{hash}", None, "", hdrs)
        return data

    def get_file(self, app: str, slot: str, snap: str, path: str) -> bytes:
        _, _, data = self._call("GET", f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots/{_enc(snap)}/files/{_segs(path)}")
        return data

    def download_archive(self, app: str, slot: str, snap: str, fileobj: Any) -> None:
        req = urllib.request.Request(
            self._base + f"/v1/apps/{_enc(app)}/slots/{_enc(slot)}/snapshots/{_enc(snap)}/archive.tar",
            headers={"Authorization": f"Bearer {self._token}", "User-Agent": self._ua})
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            while True:
                b = resp.read(1 << 16)
                if not b:
                    break
                fileobj.write(b)

    # tokens
    def list_tokens(self) -> Any:
        return self._json("GET", "/v1/tokens")

    def create_token(self, name: str, scopes: List[str]) -> Dict[str, Any]:
        return self._json("POST", "/v1/tokens", self._enc_body({"name": name, "scopes": scopes}))

    def get_token(self, id: str) -> Dict[str, Any]:
        return self._json("GET", f"/v1/tokens/{_enc(id)}")

    def patch_token(self, id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        return self._json("PATCH", f"/v1/tokens/{_enc(id)}", self._enc_body(patch))

    def revoke_token(self, id: str) -> None:
        self._call("DELETE", f"/v1/tokens/{_enc(id)}")

    def token_events(self, id: str) -> Any:
        return self._json("GET", f"/v1/tokens/{_enc(id)}/events")

    def token_stats(self, id: str) -> Dict[str, Any]:
        return self._json("GET", f"/v1/tokens/{_enc(id)}/stats")

    # vault
    def vault_get(self) -> Dict[str, Any]:
        return self._json("GET", "/v1/vault")

    def vault_put(self, v: Dict[str, Any]) -> None:
        self._call("PUT", "/v1/vault", self._enc_body(v), "application/json")

    def vault_delete(self) -> None:
        self._call("DELETE", "/v1/vault")

    # events
    def stream_events(self, last_id: Optional[str] = None) -> Generator[Dict[str, str], None, None]:
        """Yields events; reconnects with Last-Event-ID on drop."""
        lid = last_id or ""
        wait = 0.5
        while True:
            hdrs = {"Accept": "text/event-stream"}
            if lid:
                hdrs["Last-Event-ID"] = lid
            try:
                _, _, data = self._call("GET", "/v1/events", None, "", hdrs)
            except SavesError:
                import random
                wait = min(wait * 2, 10.0)
                time.sleep(wait + random.random() * wait / 4)
                continue
            name, data_s = "", ""
            wait = 0.5
            for line in data.decode("utf-8", "replace").splitlines():
                if not line:
                    if data_s:
                        yield {"id": lid, "name": name or "message", "data": data_s}
                    name, data_s = "", ""
                elif line.startswith("event:"):
                    name = line[6:].strip()
                elif line.startswith("data:"):
                    data_s = line[5:].strip()
                elif line.startswith("id:"):
                    lid = line[3:].strip()
            time.sleep(0.5)
