"""Persistent consumption and revocation state.

Backed by SQLite so that:
- concurrent consumption is serialized by an IMMEDIATE transaction, so
  the cumulative use count can never exceed the authorized maximum;
- committed use counts never roll back across process restarts;
- a consumption either commits fully or not at all (no partial writes);
- revoked token ids remain distinguishable from never-issued ones even
  after expired state is cleaned up (revocation tombstones are kept).
"""

from __future__ import annotations

import sqlite3
import threading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS grants (
    token_id   TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    uses       INTEGER NOT NULL DEFAULT 0,
    revoked    INTEGER NOT NULL DEFAULT 0,
    revoked_at INTEGER
);
"""

# Outcomes of a consume attempt, deterministic and safe to audit.
CONSUME_OK = "ok"
CONSUME_EXHAUSTED = "exhausted"
CONSUME_REVOKED = "revoked"
CONSUME_UNKNOWN = "unknown"


class StateStore:
    """Durable record of issued, consumed and revoked grants."""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.isolation_level = None  # explicit transaction control
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def register_issued(self, token_id: str, expires_at: int) -> None:
        """Record that a token id was legitimately issued."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO grants (token_id, expires_at) VALUES (?, ?)",
                (token_id, expires_at),
            )

    def try_consume(self, token_id: str, max_uses: int | None) -> tuple[str, int]:
        """Atomically increment usage if the grant allows it.

        Returns (status, uses_after) where status is one of CONSUME_*.
        The revocation check and the increment commit in the same
        transaction, so a revoke racing a consume yields a deterministic
        result and never a partial write.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT uses, revoked FROM grants WHERE token_id = ?",
                    (token_id,),
                ).fetchone()
                if row is None:
                    self._conn.execute("ROLLBACK")
                    return CONSUME_UNKNOWN, 0
                uses, revoked = row
                if revoked:
                    self._conn.execute("ROLLBACK")
                    return CONSUME_REVOKED, uses
                if max_uses is not None and uses >= max_uses:
                    self._conn.execute("ROLLBACK")
                    return CONSUME_EXHAUSTED, uses
                self._conn.execute(
                    "UPDATE grants SET uses = uses + 1 WHERE token_id = ?",
                    (token_id,),
                )
                self._conn.execute("COMMIT")
                return CONSUME_OK, uses + 1
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def usage_of(self, token_id: str) -> int | None:
        """Current use count, or None if the id was never issued."""
        with self._lock:
            row = self._conn.execute(
                "SELECT uses FROM grants WHERE token_id = ?", (token_id,)
            ).fetchone()
        return None if row is None else row[0]

    def revoke(self, token_ids: list[str], now: int) -> int:
        """Revoke ids (single or batch); returns how many were newly revoked.

        Unknown ids get a tombstone row so a revoked id stays
        distinguishable from a never-issued one.
        """
        newly = 0
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for token_id in token_ids:
                    cur = self._conn.execute(
                        """
                        INSERT INTO grants (token_id, expires_at, revoked, revoked_at)
                        VALUES (?, 0, 1, ?)
                        ON CONFLICT(token_id) DO UPDATE SET
                            revoked = 1, revoked_at = excluded.revoked_at
                        WHERE grants.revoked = 0
                        """,
                        (token_id, now),
                    )
                    newly += cur.rowcount
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return newly

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT revoked FROM grants WHERE token_id = ?", (token_id,)
            ).fetchone()
        return bool(row and row[0])

    def cleanup_expired(self, now: int) -> int:
        """Drop rows for expired, non-revoked tokens. Revocation tombstones
        are kept so revoked ids stay distinguishable from never-issued ones.
        Returns the number of rows removed."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM grants WHERE expires_at < ? AND revoked = 0", (now,)
            )
            return cur.rowcount
