"""Bounded binary COPY decoder for one ordered PostgreSQL TEXT column.

No SQL, connection, file, or mutation API. The atomic clone worker supplies the
same ordered JSON-text SELECT and the unchanged snapshot budget. Framing is
strict and fail-closed; this transport is not an accepted recovery receipt.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import paper_runtime_snapshot_worker as snapshot

HEADER = b"PGCOPY\n\xff\r\n\x00" + b"\x00" * 8
MAX_CHUNK_BYTES = 8 * 1024 * 1024


class OrderedTextDigest:
    """Incrementally consume binary COPY without buffering a table or batch.

    Only the current field (at most4MiB) and previous row for C-order validation
    are retained. Unknown flags/extensions, NULL, extra columns, invalid UTF-8,
    truncated frames, missing trailer, and mismatched COPY count are rejected.
    """

    def __init__(self, budget: Any) -> None:
        self.budget = budget
        self._hash = hashlib.sha256()
        self._count = 0
        self._previous: bytes | None = None
        self._pending = bytearray()
        self._state = "header"
        self._needed = len(HEADER)
        self._failed = False
        self._sealed = False

    def _reject(self) -> None:
        self._failed = True
        raise snapshot.SnapshotError("ordered history COPY framing/bound differs")

    def _deadline(self) -> None:
        if time.monotonic() - self.budget.started > snapshot.MAX_SECONDS:
            self._reject()

    def _frame(self, frame: bytes) -> None:
        if self._state == "header":
            if frame != HEADER:
                self._reject()
            self._state, self._needed = "fields", 2
        elif self._state == "fields":
            fields = int.from_bytes(frame, "big", signed=True)
            if fields == -1:
                self._state, self._needed = "trailer", 0
            elif fields == 1:
                self._state, self._needed = "length", 4
            else:
                self._reject()
        elif self._state == "length":
            length = int.from_bytes(frame, "big", signed=True)
            if length < 0 or length > snapshot.MAX_ROW_BYTES:
                self._reject()
            self._state, self._needed = "body", length
            if length == 0:
                self._frame(b"")
        elif self._state == "body":
            try:
                # Reuse the original row/total byte/row/time budget and exact
                # UTF-8 bytes rather than hashing COPY framing or escaped CSV.
                data = self.budget.add(frame.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, snapshot.SnapshotError):
                self._reject()
            if data != frame or (self._previous is not None and data < self._previous):
                self._reject()
            self._hash.update(len(data).to_bytes(8, "big"))
            self._hash.update(data)
            self._previous = data
            self._count += 1
            self._state, self._needed = "fields", 2
        else:
            self._reject()

    async def write(self, chunk: bytes | bytearray) -> None:
        """asyncpg's coroutine sink; no network or blocking work is introduced."""
        if self._failed or self._sealed or type(chunk) not in (bytes, bytearray) or len(chunk) > MAX_CHUNK_BYTES:
            self._reject()
        self._deadline()
        # asyncpg's native protocol may supply bytearray. Freeze that bounded
        # chunk before parsing; never retain a caller-owned mutable view.
        if type(chunk) is bytearray:
            chunk = bytes(chunk)
        offset = 0
        view = memoryview(chunk)
        while offset < len(view):
            if self._state == "trailer":
                self._reject()
            take = min(self._needed - len(self._pending), len(view) - offset)
            self._pending.extend(view[offset:offset + take])
            offset += take
            if len(self._pending) == self._needed:
                frame = bytes(self._pending)
                self._pending.clear()
                self._frame(frame)
            self._deadline()

    def finish(self, command_status: str) -> dict[str, Any]:
        if self._failed or self._sealed or self._state != "trailer" or self._pending or command_status != f"COPY {self._count}":
            self._reject()
        self._deadline()
        self._sealed = True
        return {"count": self._count, "row_digest_sha256": self._hash.hexdigest()}
