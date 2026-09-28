"""Core domain models: grants, verification decisions and audit events."""

from __future__ import annotations

from dataclasses import dataclass

# Allowed operations on a resource.
OP_READ = "read"
OP_WRITE = "write"
OP_DELETE = "delete"
ALLOWED_OPERATIONS = frozenset({OP_READ, OP_WRITE, OP_DELETE})

# Lifecycle states persisted for a grant.
STATE_ACTIVE = "active"
STATE_REVOKED = "revoked"
STATE_TOMBSTONE = "tombstone"


@dataclass(frozen=True)
class Grant:
    """Server-side record of an issued presigned grant."""

    grant_id: str
    resource_path: str
    operation: str
    expires_at: int
    max_uses: int | None
    used_count: int
    state: str
    key_id: str
    issuer: str
    consumer: str | None
    created_at: int
    revoked_at: int | None = None
    revoke_batch_id: str | None = None


@dataclass(frozen=True)
class PresignedURL:
    """A signed URL together with its parsed constraints."""

    url: str
    grant_id: str
    resource_path: str
    operation: str
    expires_at: int
    max_uses: int | None
    issued_at: int
    key_id: str
    signature: str


@dataclass(frozen=True)
class ConsumeResult:
    granted: bool
    grant_id: str
    reason: str | None = None
    used_count: int = 0
    max_uses: int | None = None


@dataclass(frozen=True)
class AuditEvent:
    id: int | None
    event_time: int
    event_type: str
    grant_id: str | None
    caller_id: str | None
    resource_path: str | None
    operation: str | None
    result: str
    reason: str | None
    detail: str | None


@dataclass(frozen=True)
class SigningKey:
    """A versioned HMAC signing key."""

    key_id: str
    secret: bytes
    created_at: int
    rotated_at: int | None = None
