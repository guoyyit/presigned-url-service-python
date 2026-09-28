"""Runtime configuration loaded from environment variables.

Configuration items
--------------------
PRESIGNED_DB_PATH
    SQLite file used for grants, usage counters, keys and audit events.
    Default: ``presigned.db``. ``:memory:`` is allowed for tests.
PRESIGNED_CLOCK_SKEW_SECONDS
    Tolerance applied to *both sides* of expiry checks (consumer clocks may
    be slightly ahead or behind). Default ``0``.
PRESIGNED_KEY_GRACE_SECONDS
    After a signing key is rotated, grants signed with the previous key stay
    verifiable for this many seconds. Default ``86400`` (1 day).
PRESIGNED_SIGN_ALG
    Signature algorithm label embedded in signed grants. Default
    ``HMAC-SHA256``.
PRESIGNED_BASE_URL
    Public base of the service, used when generating presigned URLs.
    Default ``http://localhost:8000``.
PRESIGNED_CALLERS_FILE
    Optional JSON file mapping API tokens to caller identities and scopes::

        {
          "token-issuer-a": {
            "caller_id": "team-a",
            "path_prefixes": ["/data/a/"],
            "operations": ["read"]
          }
        }

    When unset, a single development caller ``dev`` with full scope and token
    ``dev-token`` is created (development only).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

DEFAULT_SIGN_ALG = "HMAC-SHA256"


@dataclass(frozen=True)
class CallerScope:
    """Issuance/consumption restrictions attached to a caller identity."""

    caller_id: str
    path_prefixes: tuple[str, ...]
    operations: tuple[str, ...]
    api_token: str = ""

    def path_allowed(self, resource_path: str) -> bool:
        return any(
            resource_path == prefix.rstrip("/") or resource_path.startswith(prefix)
            for prefix in self.path_prefixes
        )

    def operation_allowed(self, operation: str) -> bool:
        return operation in self.operations


@dataclass(frozen=True)
class Settings:
    database_path: str
    clock_skew_seconds: int
    key_grace_period_seconds: int
    sign_alg: str
    base_url: str
    callers: tuple[CallerScope, ...] = field(default_factory=tuple)

    def caller(self, caller_id: str) -> CallerScope | None:
        for c in self.callers:
            if c.caller_id == caller_id:
                return c
        return None

    def scope_for_token(self, token: str) -> CallerScope | None:
        for c in self.callers:
            if c.api_token == token:
                return c
        return None


def _parse_callers(raw: str | None) -> tuple[CallerScope, ...]:
    if not raw:
        return (
            CallerScope(
                caller_id="dev",
                path_prefixes=("/",),
                operations=("read", "write", "delete"),
                api_token="dev-token",
            ),
        )
    with open(raw, encoding="utf-8") as fh:
        data = json.load(fh)
    callers: list[CallerScope] = []
    for token, spec in data.items():
        prefixes = tuple(spec["path_prefixes"])
        operations = tuple(spec["operations"])
        callers.append(
            CallerScope(
                caller_id=str(spec["caller_id"]),
                path_prefixes=prefixes,
                operations=operations,
                api_token=str(token),
            )
        )
    if not callers:
        raise ValueError("callers file must define at least one caller")
    return tuple(callers)


def load_settings() -> Settings:
    """Build settings from environment variables."""
    return Settings(
        database_path=os.environ.get("PRESIGNED_DB_PATH", "presigned.db"),
        clock_skew_seconds=int(os.environ.get("PRESIGNED_CLOCK_SKEW_SECONDS", "0")),
        key_grace_period_seconds=int(
            os.environ.get("PRESIGNED_KEY_GRACE_SECONDS", "86400")
        ),
        sign_alg=os.environ.get("PRESIGNED_SIGN_ALG", DEFAULT_SIGN_ALG),
        base_url=os.environ.get("PRESIGNED_BASE_URL", "http://localhost:8000"),
        callers=_parse_callers(os.environ.get("PRESIGNED_CALLERS_FILE")),
    )
