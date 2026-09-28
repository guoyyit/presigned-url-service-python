"""Domain error types.

Each error maps to a stable ``code`` so audit records and HTTP responses
can stay machine readable.
"""

from __future__ import annotations


class PresignedError(Exception):
    """Base class for all presigned-url domain errors."""

    code = "presigned_error"

    def __init__(self, message: str = "", *, grant_id: str | None = None):
        super().__init__(message or self.code)
        self.message = message or self.code
        self.grant_id = grant_id


class InvalidRequestError(PresignedError):
    code = "invalid_request"


class ScopeDeniedError(PresignedError):
    """Caller is not allowed to issue or consume a grant."""

    code = "scope_denied"


class InvalidSignatureError(PresignedError):
    code = "invalid_signature"


class GrantExpiredError(PresignedError):
    code = "grant_expired"


class GrantRevokedError(PresignedError):
    code = "grant_revoked"


class GrantNotFoundError(PresignedError):
    """The grant id is unknown and has never been issued."""

    code = "grant_not_found"


class UsageExhaustedError(PresignedError):
    code = "usage_exhausted"


class ConstraintViolationError(PresignedError):
    code = "constraint_violation"


class StorageError(PresignedError):
    code = "storage_error"
