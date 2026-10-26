# SPDX-License-Identifier: 0BSD
"""SSE convenience wrapper."""

from typing import Any, Dict, Generator, Optional

from .client import SavesClient


def stream_events(client: SavesClient, last_id: Optional[str] = None) -> Generator[Dict[str, str], None, None]:
    """Yields SSE events from /v1/events."""
    yield from client.stream_events(last_id)
