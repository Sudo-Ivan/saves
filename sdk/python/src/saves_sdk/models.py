# SPDX-License-Identifier: 0BSD
"""Wire shapes for the saves API."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ChunkRef:
    h: str
    n: int


@dataclass
class FileEntry:
    path: str
    size: int
    mode: int = 0
    mtime_ns: int = 0
    chunks: Optional[List[ChunkRef]] = None
    inline: Optional[str] = None


@dataclass
class Manifest:
    version: int = 1
    device: str = ""
    label: str = ""
    parent: Optional[str] = None
    enc: object = None
    dirs: List[str] = field(default_factory=list)
    files: List[FileEntry] = field(default_factory=list)


@dataclass
class BeginOut:
    id: str
    missing: List[str] = field(default_factory=list)


@dataclass
class Slot:
    slot: str = ""
    head: str = ""


@dataclass
class Snapshot:
    id: str = ""
    label: str = ""
    device: str = ""
    enc: bool = False


@dataclass
class Token:
    id: str = ""
    name: str = ""
    scopes: List[str] = field(default_factory=list)


@dataclass
class TokenStats:
    total_requests: int = 0
    requests_24h: int = 0
    requests_30d: int = 0
