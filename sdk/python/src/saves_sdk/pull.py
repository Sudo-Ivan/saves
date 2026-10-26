# SPDX-License-Identifier: 0BSD
"""High level pull helper."""

import base64
import hashlib
import os
from pathlib import Path
from typing import Callable, Optional

from .client import SavesClient
from .errors import SavesError


def _safe(path: str) -> None:
    if path.startswith("/") or "\\" in path or any(
            s in ("", ".", "..") for s in path.split("/")):
        raise SavesError("unsafe path")


def pull(client: SavesClient, app: str, slot: str, snapshot_id: str,
         directory: str, prune: bool = False,
         on_progress: Optional[Callable[[int, int], None]] = None) -> None:
    """Downloads a snapshot into a directory."""
    m = client.get_manifest(app, slot, snapshot_id)
    if m.enc:
        e = SavesError("snapshot is encrypted")
        e.status = 409
        e.code = "encrypted"
        raise e
    dest = Path(directory)
    total = sum(f.size for f in m.files)
    done = 0
    seen = set()
    for f in m.files:
        _safe(f.path)
        dst = dest / f.path
        dst.parent.mkdir(parents=True, exist_ok=True)
        if f.inline is not None:
            data = base64.b64decode(f.inline)
        else:
            from concurrent.futures import ThreadPoolExecutor
            refs = f.chunks or []
            def get(i_ref):
                i, c = i_ref
                b = client.get_chunk(app, c.h)
                if hashlib.sha256(b).hexdigest() != c.h:
                    raise SavesError("chunk hash mismatch")
                return i, b
            if refs:
                with ThreadPoolExecutor(max_workers=4) as ex:
                    parts = [b for _, b in sorted(ex.map(get, enumerate(refs)))]
            else:
                parts = []
            data = b"".join(parts)
        if len(data) != f.size:
            raise SavesError("size mismatch")
        tmp = dst.with_name(dst.name + ".saves-tmp")
        tmp.write_bytes(data)
        try:
            os.chmod(tmp, f.mode & 0o777)
        except OSError:
            pass
        os.replace(tmp, dst)
        try:
            os.utime(dst, ns=(int(f.mtime_ns), int(f.mtime_ns)))
        except OSError:
            pass
        seen.add(dst)
        done += f.size
        if on_progress:
            on_progress(done, total)
    for d in m.dirs:
        p = dest / d
        p.mkdir(parents=True, exist_ok=True)
        seen.add(p)
    if prune:
        for p in dest.rglob("*"):
            if p.is_file() and p not in seen:
                p.unlink()
