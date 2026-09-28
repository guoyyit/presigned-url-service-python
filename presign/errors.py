"""Domain errors for the presigned URL service.

Each failure mode maps to a stable, auditable reason code so that
callers and audit records can distinguish *why* an access was denied.
"""

from __future__ import annotations

from enum import StrEnum


class DenyReason(StrEnum):
    """Machine-readable reasons an access or issuance was denied."""

    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    KEY_RETIRED = "key_retired"
    REVOKED = "revoked"
    UNKNOWN_TOKEN = "unknown_token"
    USAGE_EXHAUSTED = "usage_exhausted"
    OPERATION_NOT_ALLOWED = "operation_not_allowed"
    RESOURCE_MISMATCH = "resource_mismatch"
    OUT_OF_SCOPE = "out_of_scope"


class PresignError(Exception):
    """Base class for all presign domain errors."""


class IssueDenied(PresignError):
    """Raised when an issuance request exceeds the issuer's scope."""

    def __init__(self, reason: DenyReason, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else str(reason))
        self.reason = reason
        self.detail = detail


class AccessDenied(PresignError):
    """Raised when a presigned URL fails verification or consumption."""

    def __init__(self, reason: DenyReason, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else str(reason))
        self.reason = reason
        self.detail = detail
