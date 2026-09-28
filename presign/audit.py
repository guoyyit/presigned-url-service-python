"""Append-only audit trail for issuance, access, rotation and revocation.

Each record is one JSON object per line (JSONL). Writes are serialized
by a lock and flushed+fsync'd so the trail survives process restarts
and concurrent producers never interleave a line.
"""

from __future__ import annotations

import json
import os
import threading
import time


class AuditLogger:
    """Writes one JSON object per line; safe for concurrent writers."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)

    def record(self, event: str, **fields: object) -> None:
        entry = {"ts": int(time.time()), "event": event, **fields}
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
