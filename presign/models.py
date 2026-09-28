"""Core data model for presigned URL issuance and consumption.

A *grant* is the set of constraints encoded into (and authenticated by)
a presigned URL. A *token* is the URL-safe string handed to the third
party. Consumption and revocation state live in the store, keyed by the
grant's unique id.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Operation(StrEnum):
    """Operations a grant may authorize."""

    READ = "read"


@dataclass(frozen=True, slots=True)
class Scope:
    """Limits within which an identity may issue grants."""

    identity: str
    resource_prefix: str
    operations: frozenset[Operation]


@dataclass(frozen=True, slots=True)
class IssueRequest:
    """Parameters requested for a new grant."""

    resource: str
    operation: Operation
    expires_at: int  # unix seconds
    max_uses: int | None = None  # None means unlimited while valid
    issuer: str = "anonymous"


@dataclass(frozen=True, slots=True)
class ConsumeResult:
    """Outcome of one access attempt against a presigned URL."""

    allowed: bool
    reason: str
    token_id: str | None
    uses_after: int | None
    remaining: int | None
