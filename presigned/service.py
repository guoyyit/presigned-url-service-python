"""Application service: issuance, verification/consumption, revocation, audit.

The service is the only place that combines cryptographic verification with
durable state. Every decision (success or denial) is written to the audit
log, and every use-count change goes through the atomic storage transaction.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from presigned.clock import Clock, SystemClock
from presigned.config import Settings
from presigned.crypto import KeyStore
from presigned.errors import (
    ConstraintViolationError,
    GrantExpiredError,
    GrantNotFoundError,
    GrantRevokedError,
    InvalidRequestError,
    InvalidSignatureError,
    PresignedError,
    ScopeDeniedError,
    UsageExhaustedError,
)
from presigned.models import (
    ALLOWED_OPERATIONS,
    AuditEvent,
    ConsumeResult,
    Grant,
    PresignedURL,
    STATE_ACTIVE,
    STATE_REVOKED,
    STATE_TOMBSTONE,
)
from presigned.signing import sign_grant, verify_url
from presigned.storage import Storage

RESULT_SUCCESS = "success"
RESULT_DENIED = "denied"


class PresignedService:
    def __init__(
        self,
        *,
        settings: Settings,
        storage: Storage,
        keys: KeyStore,
        clock: Clock,
        base_url: str,
    ) -> None:
        self.settings = settings
        self.storage = storage
        self.keys = keys
        self.clock = clock
        self.base_url = base_url.rstrip("/")

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------
    def issue(
        self,
        *,
        caller_id: str,
        resource_path: str,
        operation: str,
        ttl_seconds: int,
        max_uses: int | None,
        consumer: str | None = None,
    ) -> PresignedURL:
        scope = self.settings.caller(caller_id)
        if scope is None:
            self._audit(
                "issue",
                grant_id=None,
                caller_id=caller_id,
                resource_path=resource_path,
                operation=operation,
                result=RESULT_DENIED,
                reason="unknown_caller",
            )
            raise ScopeDeniedError("caller identity is not registered")

        if operation not in ALLOWED_OPERATIONS:
            raise InvalidRequestError(f"unsupported operation: {operation}")
        if not resource_path.startswith("/"):
            raise InvalidRequestError("resource_path must start with '/'")
        if ttl_seconds <= 0:
            raise InvalidRequestError("ttl_seconds must be positive")
        if max_uses is not None and max_uses < 1:
            raise InvalidRequestError("max_uses must be >= 1")

        if not scope.operation_allowed(operation) or not scope.path_allowed(resource_path):
            self._audit(
                "issue",
                grant_id=None,
                caller_id=caller_id,
                resource_path=resource_path,
                operation=operation,
                result=RESULT_DENIED,
                reason="outside_caller_scope",
                detail=f"prefixes={scope.path_prefixes} operations={scope.operations}",
            )
            raise ScopeDeniedError("resource or operation is outside caller scope")

        now = self.clock.now()
        grant_id = uuid.uuid4().hex
        expires_at = now + int(ttl_seconds)
        key = self.keys.current()

        grant = Grant(
            grant_id=grant_id,
            resource_path=resource_path,
            operation=operation,
            expires_at=expires_at,
            max_uses=max_uses,
            used_count=0,
            state=STATE_ACTIVE,
            key_id=key.key_id,
            issuer=caller_id,
            consumer=consumer,
            created_at=now,
        )
        self.storage.insert_grant(grant)
        signed = sign_grant(
            base_url=self.base_url,
            grant_id=grant_id,
            resource_path=resource_path,
            operation=operation,
            expires_at=expires_at,
            max_uses=max_uses,
            issued_at=now,
            keys=self.keys,
            alg=self.settings.sign_alg,
        )
        self._audit(
            "issue",
            grant_id=grant_id,
            caller_id=caller_id,
            resource_path=resource_path,
            operation=operation,
            result=RESULT_SUCCESS,
            detail=f"key_id={key.key_id} ttl={ttl_seconds} max_uses={max_uses}",
        )
        return signed

    # ------------------------------------------------------------------
    # Consumption
    # ------------------------------------------------------------------
    def verify_only(self, raw_url: str) -> Grant:
        """Validate signature/expiry/constraints without consuming a use."""
        parsed = self._verify_parsed(raw_url)
        grant = self._load_matching_grant(parsed, consumer=None, check_consumer=False)
        self._check_lifecycle(grant, parsed)
        return grant

    def consume_url(self, raw_url: str, *, consumer: str | None = None) -> ConsumeResult:
        """Validate and atomically consume one use; always audited."""
        try:
            parsed = self._verify_parsed(raw_url)
        except PresignedError as exc:
            gid = getattr(exc, "grant_id", None)
            self._audit_consume_denied(gid, consumer, None, None, exc)
            return ConsumeResult(granted=False, grant_id=gid or "", reason=exc.code)

        try:
            grant = self._load_matching_grant(parsed, consumer=consumer, check_consumer=True)
            self._check_lifecycle(grant, parsed)
        except PresignedError as exc:
            self._audit_consume_denied(parsed.grant_id, consumer, parsed.resource_path,
                                      parsed.operation, exc)
            return ConsumeResult(
                granted=False,
                grant_id=parsed.grant_id,
                reason=exc.code,
                used_count=0,
                max_uses=parsed.max_uses,
            )

        allowed, used = self.storage.consume_grant(parsed.grant_id)
        if not allowed:
            # State changed between check and transaction (revocation) or the
            # cap was reached by a racing request: the durable row decides.
            fresh = self.storage.get_grant(parsed.grant_id)
            if fresh is not None and fresh.state != STATE_ACTIVE:
                exc: PresignedError = GrantRevokedError(
                    "grant has been revoked", grant_id=parsed.grant_id
                )
            else:
                exc = UsageExhaustedError(
                    "maximum usage count reached", grant_id=parsed.grant_id
                )
            self._audit_consume_denied(
                parsed.grant_id, consumer, parsed.resource_path, parsed.operation, exc
            )
            return ConsumeResult(
                granted=False,
                grant_id=parsed.grant_id,
                reason=exc.code,
                used_count=used,
                max_uses=parsed.max_uses,
            )

        self._audit(
            "consume",
            grant_id=parsed.grant_id,
            caller_id=consumer,
            resource_path=parsed.resource_path,
            operation=parsed.operation,
            result=RESULT_SUCCESS,
            detail=f"used={used}/{parsed.max_uses}",
        )
        return ConsumeResult(
            granted=True,
            grant_id=parsed.grant_id,
            used_count=used,
            max_uses=parsed.max_uses,
        )

    def _verify_parsed(self, raw_url: str) -> PresignedURL:
        return verify_url(raw_url, self.keys, alg=self.settings.sign_alg)

    def _load_matching_grant(
        self, parsed: PresignedURL, *, consumer: str | None, check_consumer: bool
    ) -> Grant:
        grant = self.storage.get_grant(parsed.grant_id)
        if grant is None:
            raise GrantNotFoundError("grant was never issued", grant_id=parsed.grant_id)
        if grant.state in (STATE_REVOKED, STATE_TOMBSTONE):
            raise GrantRevokedError("grant has been revoked", grant_id=parsed.grant_id)
        if (
            grant.resource_path != parsed.resource_path
            or grant.operation != parsed.operation
            or grant.expires_at != parsed.expires_at
            or grant.max_uses != parsed.max_uses
            or grant.key_id != parsed.key_id
            or grant.created_at != parsed.issued_at
        ):
            raise ConstraintViolationError(
                "signed parameters do not match the issued grant",
                grant_id=parsed.grant_id,
            )
        if check_consumer and grant.consumer is not None and grant.consumer != consumer:
            raise ScopeDeniedError(
                "caller identity is not bound to this grant",
                grant_id=parsed.grant_id,
            )
        return grant

    def _check_lifecycle(self, grant: Grant, parsed: PresignedURL) -> None:
        now = self.clock.now()
        skew = self.settings.clock_skew_seconds
        if now > grant.expires_at + skew:
            raise GrantExpiredError("grant has expired", grant_id=grant.grant_id)
        key = self.keys.get(parsed.key_id)
        if key is None:
            raise InvalidSignatureError("unknown signing key", grant_id=grant.grant_id)
        grace = self.settings.key_grace_period_seconds
        if key.rotated_at is not None and (
            grace <= 0 or now - key.rotated_at > grace
        ):
            raise InvalidSignatureError(
                "signing key grace period has ended", grant_id=grant.grant_id
            )

    def _audit_consume_denied(
        self,
        grant_id: str | None,
        consumer: str | None,
        resource_path: str | None,
        operation: str | None,
        exc: PresignedError,
    ) -> None:
        self._audit(
            "consume",
            grant_id=grant_id,
            caller_id=consumer,
            resource_path=resource_path,
            operation=operation,
            result=RESULT_DENIED,
            reason=exc.code,
            detail=exc.message,
        )

    # ------------------------------------------------------------------
    # Revocation / cleanup / status
    # ------------------------------------------------------------------
    def revoke(self, caller_id: str, grant_ids: Iterable[str]) -> dict:
        ids = list(dict.fromkeys(grant_ids))
        if not ids:
            raise InvalidRequestError("grant_ids must not be empty")
        scope = self.settings.caller(caller_id)
        if scope is None:
            raise ScopeDeniedError("caller identity is not registered")

        permitted: list[str] = []
        denied: list[str] = []
        not_found: list[str] = []
        already_revoked: list[str] = []
        for gid in ids:
            grant = self.storage.get_grant(gid)
            if grant is None:
                not_found.append(gid)
            elif grant.state in (STATE_REVOKED, STATE_TOMBSTONE):
                already_revoked.append(gid)
            elif grant.issuer != caller_id or not scope.path_allowed(grant.resource_path):
                denied.append(gid)
            else:
                permitted.append(gid)

        batch_id = "batch-" + uuid.uuid4().hex[:16]
        revoked = (
            self.storage.revoke_grants(permitted, revoked_at=self.clock.now(), batch_id=batch_id)
            if permitted
            else []
        )
        for gid in revoked:
            self._audit("revoke", grant_id=gid, caller_id=caller_id,
                        resource_path=None, operation=None,
                        result=RESULT_SUCCESS, detail=f"batch={batch_id}")
        for gid in denied:
            self._audit("revoke", grant_id=gid, caller_id=caller_id,
                        resource_path=None, operation=None,
                        result=RESULT_DENIED, reason="outside_caller_scope")
        result = {
            "batch_id": batch_id,
            "revoked": revoked,
            "not_found": not_found,
            "already_revoked": already_revoked,
            "denied": denied,
        }
        return result

    def cleanup(self, grant_ids: Iterable[str]) -> dict:
        ids = list(dict.fromkeys(grant_ids))
        if not ids:
            raise InvalidRequestError("grant_ids must not be empty")
        converted = self.storage.cleanup_grants(ids)
        for gid in converted:
            self._audit("cleanup", grant_id=gid, caller_id=None,
                        resource_path=None, operation=None, result=RESULT_SUCCESS)
        return {
            "cleaned": converted,
            "unknown_or_active": [g for g in ids if g not in set(converted)],
        }

    def grant_status(self, grant_id: str) -> dict:
        grant = self.storage.get_grant(grant_id)
        if grant is None:
            return {"grant_id": grant_id, "exists": False, "state": "never_issued"}
        return {
            "grant_id": grant.grant_id,
            "exists": True,
            "state": grant.state,
            "resource_path": grant.resource_path,
            "operation": grant.operation,
            "used_count": grant.used_count,
            "max_uses": grant.max_uses,
            "expires_at": grant.expires_at,
            "issuer": grant.issuer,
            "consumer": grant.consumer,
            "revoked_at": grant.revoked_at,
            "revoke_batch_id": grant.revoke_batch_id,
        }

    # ------------------------------------------------------------------
    # Key rotation
    # ------------------------------------------------------------------
    def rotate_keys(self) -> dict:
        old_id = self.keys.current_key_id
        new = self.keys.rotate()
        self._audit(
            "key_rotate",
            grant_id=None,
            caller_id=None,
            resource_path=None,
            operation=None,
            result=RESULT_SUCCESS,
            detail=f"old_key={old_id} new_key={new.key_id}",
        )
        return {"old_key_id": old_id, "new_key_id": new.key_id}

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def audit(self, *, grant_id: str | None = None, limit: int = 100) -> list[AuditEvent]:
        return self.storage.list_audit(grant_id=grant_id, limit=limit)

    def _audit(
        self,
        event_type: str,
        *,
        grant_id: str | None,
        caller_id: str | None,
        resource_path: str | None,
        operation: str | None,
        result: str,
        reason: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.storage.append_audit(
            AuditEvent(
                id=None,
                event_time=self.clock.now(),
                event_type=event_type,
                grant_id=grant_id,
                caller_id=caller_id,
                resource_path=resource_path,
                operation=operation,
                result=result,
                reason=reason,
                detail=detail,
            )
        )


def build_service(
    settings: Settings, *, clock: Clock | None = None, storage: Storage | None = None
) -> PresignedService:
    """Wire storage, key store and clock for a given settings object."""
    clk = clock or SystemClock()
    store = storage or Storage(settings.database_path)
    keys = KeyStore(store, clk)
    return PresignedService(
        settings=settings,
        storage=store,
        keys=keys,
        clock=clk,
        base_url=settings.base_url,
    )
