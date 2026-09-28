"""Runtime configuration for the presigned URL service.

All values can be overridden via environment variables prefixed with
``PRESIGN_`` so local acceptance runs are reproducible.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .models import Operation, Scope


def _getenv(name: str, default: str) -> str:
    return os.environ.get(f"PRESIGN_{name}", default)


def _parse_scopes(raw: str) -> dict[str, Scope]:
    """Parse ``identity:prefix:op1|op2;identity2:...`` into Scope objects."""
    scopes: dict[str, Scope] = {}
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        identity, prefix, ops = chunk.split(":", 2)
        scopes[identity] = Scope(
            identity=identity,
            resource_prefix=prefix,
            operations=frozenset(Operation(op) for op in ops.split("|")),
        )
    return scopes


@dataclass(frozen=True, slots=True)
class Settings:
    """Service-wide settings.

    - ``clock_skew_seconds``: tolerance applied when checking expiry, so
      consumers with slightly skewed clocks are not rejected unfairly.
    - ``rotation_grace_seconds``: after a key rotation, tokens signed by
      the previous key remain verifiable for this long past rotation.
    - ``db_path``: SQLite file holding consumption and revocation state.
    - ``audit_log_path``: append-only JSONL audit trail.
    - ``signing_keys``: mapping of key id -> secret; the *active* key
      signs new tokens, retired keys only verify (within grace).
    """

    clock_skew_seconds: int = 30
    rotation_grace_seconds: int = 300
    db_path: str = "./presign-state.db"
    audit_log_path: str = "./presign-audit.log"
    active_key_id: str = "k1"
    signing_keys: dict[str, str] = field(
        default_factory=lambda: {"k1": "dev-only-secret-change-me"}
    )
    scopes: dict[str, Scope] = field(
        default_factory=lambda: _parse_scopes("alice:docs/:read")
    )

    @classmethod
    def from_env(cls) -> "Settings":
        keys_raw = _getenv("SIGNING_KEYS", "k1:dev-only-secret-change-me")
        keys = dict(
            pair.split(":", 1) for pair in keys_raw.split(",") if ":" in pair
        )
        return cls(
            clock_skew_seconds=int(_getenv("CLOCK_SKEW_SECONDS", "30")),
            rotation_grace_seconds=int(_getenv("ROTATION_GRACE_SECONDS", "300")),
            db_path=_getenv("DB_PATH", "./presign-state.db"),
            audit_log_path=_getenv("AUDIT_LOG_PATH", "./presign-audit.log"),
            active_key_id=_getenv("ACTIVE_KEY_ID", "k1"),
            signing_keys=keys,
            scopes=_parse_scopes(_getenv("SCOPES", "alice:docs/:read")),
        )
