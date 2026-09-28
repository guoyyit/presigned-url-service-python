"""Durable persistence for grants, usage counts, signing keys and audit logs.

SQLite is used in WAL mode with ``BEGIN IMMEDIATE`` write transactions:

* :meth:`Storage.consume_grant` performs a read-modify-write inside one
  serialized transaction, so concurrent consumers of the same grant can
  never exceed ``max_uses``.
* Every state change (issue/consume/revoke/rotate/deny) is written in the
  same transaction as the effect it describes, which prevents partial
  writes if the process is killed mid-consumption.
* Revoked grants leave a ``tombstone`` row after cleanup, so cleaned-up
  grants stay distinguishable from grants that were never issued.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterable

from presigned.models import AuditEvent, Grant, SigningKey

SCHEMA = """
CREATE TABLE IF NOT EXISTS signing_keys (
    key_id      TEXT PRIMARY KEY,
    secret      BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    rotated_at  INTEGER
);

CREATE TABLE IF NOT EXISTS grants (
    grant_id        TEXT PRIMARY KEY,
    resource_path   TEXT NOT NULL,
    operation       TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    max_uses        INTEGER,
    used_count      INTEGER NOT NULL DEFAULT 0,
    state           TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    issuer          TEXT NOT NULL,
    consumer        TEXT,
    created_at      INTEGER NOT NULL,
    revoked_at      INTEGER,
    revoke_batch_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_grants_state ON grants(state);

CREATE TABLE IF NOT EXISTS audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time    INTEGER NOT NULL,
    event_type    TEXT NOT NULL,
    grant_id      TEXT,
    caller_id     TEXT,
    resource_path TEXT,
    operation     TEXT,
    result        TEXT NOT NULL,
    reason        TEXT,
    detail        TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_grant ON audit_events(grant_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(event_time);
"""


class Storage:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.init_schema()

    # -- connection / schema ------------------------------------------
    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_schema(self) -> None:
        conn = self.connect()
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()

    def close(self) -> None:
        # Connections are short-lived; nothing to close by default.
        return None

    # -- signing keys -------------------------------------------------
    def load_keys(self) -> list[SigningKey]:
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM signing_keys").fetchall()
        finally:
            conn.close()
        return [
            SigningKey(
                key_id=r["key_id"],
                secret=bytes(r["secret"]),
                created_at=r["created_at"],
                rotated_at=r["rotated_at"],
            )
            for r in rows
        ]

    def insert_key(self, key: SigningKey) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO signing_keys (key_id, secret, created_at, rotated_at)"
                " VALUES (?, ?, ?, ?)",
                (key.key_id, key.secret, key.created_at, key.rotated_at),
            )
        finally:
            conn.close()

    def mark_key_rotated(self, key_id: str, rotated_at: int) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "UPDATE signing_keys SET rotated_at = ? WHERE key_id = ?",
                (rotated_at, key_id),
            )
        finally:
            conn.close()

    # -- grants -------------------------------------------------------
    def insert_grant(self, grant: Grant) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO grants (grant_id, resource_path, operation, expires_at,"
                " max_uses, used_count, state, key_id, issuer, consumer, created_at,"
                " revoked_at, revoke_batch_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    grant.grant_id,
                    grant.resource_path,
                    grant.operation,
                    grant.expires_at,
                    grant.max_uses,
                    grant.used_count,
                    grant.state,
                    grant.key_id,
                    grant.issuer,
                    grant.consumer,
                    grant.created_at,
                    grant.revoked_at,
                    grant.revoke_batch_id,
                ),
            )
        finally:
            conn.close()

    def _row_to_grant(self, r: sqlite3.Row) -> Grant:
        return Grant(
            grant_id=r["grant_id"],
            resource_path=r["resource_path"],
            operation=r["operation"],
            expires_at=r["expires_at"],
            max_uses=r["max_uses"],
            used_count=r["used_count"],
            state=r["state"],
            key_id=r["key_id"],
            issuer=r["issuer"],
            consumer=r["consumer"],
            created_at=r["created_at"],
            revoked_at=r["revoked_at"],
            revoke_batch_id=r["revoke_batch_id"],
        )

    def get_grant(self, grant_id: str) -> Grant | None:
        conn = self.connect()
        try:
            r = conn.execute(
                "SELECT * FROM grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
        finally:
            conn.close()
        return self._row_to_grant(r) if r is not None else None

    def consume_grant(self, grant_id: str) -> tuple[bool, int]:
        """Atomically consume one use.

        Returns ``(allowed, used_count)``. ``allowed`` is ``False`` when the
        grant is revoked/tombstoned or the usage cap is already reached; in
        that case no row is modified.
        """
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            r = conn.execute(
                "SELECT state, used_count, max_uses FROM grants WHERE grant_id = ?",
                (grant_id,),
            ).fetchone()
            if r is None or r["state"] != "active":
                conn.execute("ROLLBACK")
                return False, (r["used_count"] if r is not None else 0)
            if r["max_uses"] is not None and r["used_count"] >= r["max_uses"]:
                conn.execute("ROLLBACK")
                return False, r["used_count"]
            cur = conn.execute(
                "UPDATE grants SET used_count = used_count + 1 WHERE grant_id = ?",
                (grant_id,),
            )
            used = r["used_count"] + 1
            conn.execute("COMMIT")
            return cur.rowcount == 1, used
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def revoke_grants(
        self, grant_ids: Iterable[str], *, revoked_at: int, batch_id: str
    ) -> list[str]:
        """Mark currently active grants revoked. Returns affected grant ids."""
        ids = list(dict.fromkeys(grant_ids))
        if not ids:
            return []
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in ids)
            affected = [
                row["grant_id"]
                for row in conn.execute(
                    f"SELECT grant_id FROM grants WHERE grant_id IN ({placeholders})"
                    " AND state = 'active'",
                    ids,
                ).fetchall()
            ]
            if affected:
                aph = ",".join("?" for _ in affected)
                conn.execute(
                    f"UPDATE grants SET state = 'revoked', revoked_at = ?,"
                    f" revoke_batch_id = ? WHERE grant_id IN ({aph})",
                    [revoked_at, batch_id, *affected],
                )
            conn.execute("COMMIT")
            return affected
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def cleanup_grants(self, grant_ids: Iterable[str]) -> list[str]:
        """Collapse revoked grants into tombstones (constraints erased).

        Returns the grant ids actually converted. A tombstone row survives so
        the id remains distinguishable from one that was never issued.
        """
        ids = list(dict.fromkeys(grant_ids))
        if not ids:
            return []
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in ids)
            rows = conn.execute(
                f"SELECT grant_id, created_at, revoked_at, revoke_batch_id, issuer"
                f" FROM grants WHERE grant_id IN ({placeholders}) AND state = 'revoked'",
                ids,
            ).fetchall()
            for r in rows:
                conn.execute(
                    "UPDATE grants SET resource_path = '', operation = '',"
                    " expires_at = 0, max_uses = NULL, used_count = 0, key_id = '',"
                    " consumer = NULL, state = 'tombstone' WHERE grant_id = ?",
                    (r["grant_id"],),
                )
            conn.execute("COMMIT")
            return [r["grant_id"] for r in rows]
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # -- audit --------------------------------------------------------
    def append_audit(self, event: AuditEvent) -> int:
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO audit_events (event_time, event_type, grant_id,"
                " caller_id, resource_path, operation, result, reason, detail)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    event.event_time,
                    event.event_type,
                    event.grant_id,
                    event.caller_id,
                    event.resource_path,
                    event.operation,
                    event.result,
                    event.reason,
                    event.detail,
                ),
            )
            return int(cur.lastrowid)
        finally:
            conn.close()

    def list_audit(
        self, *, grant_id: str | None = None, limit: int = 100
    ) -> list[AuditEvent]:
        conn = self.connect()
        try:
            if grant_id is not None:
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE grant_id = ?"
                    " ORDER BY id DESC LIMIT ?",
                    (grant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        finally:
            conn.close()
        return [
            AuditEvent(
                id=r["id"],
                event_time=r["event_time"],
                event_type=r["event_type"],
                grant_id=r["grant_id"],
                caller_id=r["caller_id"],
                resource_path=r["resource_path"],
                operation=r["operation"],
                result=r["result"],
                reason=r["reason"],
                detail=r["detail"],
            )
            for r in rows
        ]
