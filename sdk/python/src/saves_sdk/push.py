# SPDX-License-Identifier: 0BSD
"""High level push helper."""

import base64
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .client import SavesClient
from .errors import SavesError
from .models import ChunkRef, FileEntry, Manifest


def _safe_rel(path: str) -> None:
    if path.startswith("/") or "\\" in path or any(
            s in ("", ".", "..") for s in path.split("/")):
        raise SavesError("unsafe path")


def push(client: SavesClient, app: str, slot: str, directory: str,
         root: str = "save", label: Optional[str] = None,
         device: Optional[str] = None, force: bool = False,
         chunk_size: Optional[int] = None, parallelism: int = 4,
         on_progress: Optional[Callable[[int, int], None]] = None) -> str:
    """Uploads a directory as a snapshot; returns the committed head id."""
    me = client.me()
    lim = me.get("limits", {})
    inline_max = int(lim.get("inline_max_bytes", 64 << 10))
    cs = int(chunk_size or (1 << 20))
    cs = max(cs, int(lim.get("min_chunk_bytes", 256 << 10)))
    cs = min(cs, int(lim.get("max_chunk_bytes", 8 << 20)))

    files: List[Tuple[str, Path, int, int, int]] = []
    dirs: List[str] = []
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames.sort()
        rel = os.path.relpath(dirpath, directory)
        for d in dirnames:
            dirs.append(f"{root}/{rel}/{d}" if rel != "." else f"{root}/{d}")
        for fn in sorted(filenames):
            full = Path(dirpath) / fn
            if full.is_symlink():
                continue
            st = full.stat()
            rp = f"{root}/{rel}/{fn}" if rel != "." else f"{root}/{fn}"
            files.append((rp, full, st.st_size, st.st_mode & 0o777,
                          int(st.st_mtime_ns)))
    files.sort(key=lambda f: f[0])

    mfiles: List[FileEntry] = []
    chunks: List[Tuple[str, Path, int, int]] = []
    total = 0
    for rel, full, size, mode, mt in files:
        total += size
        fe = FileEntry(path=rel, size=size, mode=mode, mtime_ns=mt)
        if size <= inline_max:
            fe.inline = base64.b64encode(full.read_bytes()).decode()
        else:
            data = full.read_bytes()
            refs: List[ChunkRef] = []
            off = 0
            while off < size:
                chunk = data[off:off + cs]
                h = hashlib.sha256(chunk).hexdigest()
                refs.append(ChunkRef(h=h, n=len(chunk)))
                chunks.append((h, full, off, len(chunk)))
                off += len(chunk)
            fe.chunks = refs
        mfiles.append(fe)

    head = ""
    try:
        head = client.get_slot(app, slot).get("head", "")
    except SavesError:
        pass
    m = Manifest(device=device or "", label=label or "",
                 parent=head or None, dirs=dirs, files=mfiles)
    bo = client.begin_snapshot(app, slot, head or None, m)

    missing = set(bo.missing)
    jobs = [c for c in chunks if c[0] in missing]
    done = [0]
    import threading
    lock = threading.Lock()

    def upload(h: str, full: Path, off: int, ln: int) -> None:
        with open(full, "rb") as fh:
            fh.seek(off)
            buf = fh.read(ln)
        client.put_chunk(app, slot, bo.id, h, buf)
        with lock:
            done[0] += ln
            if on_progress:
                on_progress(done[0], total)

    with ThreadPoolExecutor(max_workers=parallelism) as ex:
        list(ex.map(lambda j: upload(*j), jobs))

    res = client.commit_snapshot(app, slot, bo.id, if_match=head or None, force=force)
    return str(res.get("head", bo.id))
