# SPDX-License-Identifier: 0BSD
"""Error type for the saves API."""

from typing import Optional


class SavesError(Exception):
    """Raised on saves API failures."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.status: int = 0
        self.code: str = "internal"
        self.title: str = ""
        self.detail: str = ""
        self.request_id: str = ""
        self.retry_after: Optional[int] = None
        self.head: Optional[str] = None
