"""Orchestrates issuance, verification, consumption, rotation and revocation.

Token format: a URL path whose query string carries *all* constraint
parameters plus the key id and the HMAC-SHA256 signature::

    /presign/access?tid=..&r=..&op=..&exp=..&mu=..&iat=..&iss=..&kid=..&sig=..

The signature covers a canonical, versioned encoding of every
constraint field, so tampering with any parameter invalidates it.
"""

from __future__ import annotations

import uuid
from urllib.parse import parse_qs, urlencode, urlparse

from .audit import AuditLogger
from .errors import AccessDenied, DenyReason, IssueDenied
from .models import ConsumeResult, IssueRequest, Operation, Scope
from .signing import KeyStore
from .store import (
    CONSUME_EXHAUSTED,
    CONSUME_OK,
    CONSUME_REVOKED,
    CONSUME_UNKNOWN,
    StateStore,
)

ACCESS_PATH = "/presign/access"
_TOKEN_VERSION = "v1"


def _canonical_payload(
    *,
    tid: str,
    resource: str,
    operation: str,
    exp: int,
    max_uses: int | None,
    iat: int,
    issuer: str,
    kid: str,
) -> bytes:
    """Deterministic, versioned encoding of every signed constraint."""
    fields = [
        _TOKEN_VERSION,
        tid,
        resource,
        operation,
        str(exp),
        "" if max_uses is None else str(max_uses),
        str(iat),
        issuer,
        kid,
    ]
    return "\n".join(fields).encode("utf-8")


class PresignService:
    """Facade combining signing, persistent state and auditing."""

    def __init__(
        self,
        keys: KeyStore,
        store: StateStore,
        audit: AuditLogger,
        clock_skew_seconds: int = 30,
        rotation_grace_seconds: int = 300,
        scopes: dict[str, Scope] | None = None,
    ) -> None:
        self._keys = keys
        self._store = store
        self._audit = audit
        self._clock_skew = clock_skew_seconds
        self._rotation_grace = rotation_grace_seconds
        self._scopes = scopes or {}

    def scope_for(self, identity: str) -> Scope | None:
        """The issuance scope registered for ``identity``, if any."""
        return self._scopes.get(identity)

    # ------------------------------------------------------------------ issue

    def issue(self, request: IssueRequest, scope: Scope, now: int) -> str:
        """Issue a presigned URL for ``request`` if it fits within ``scope``.

        Raises IssueDenied (and audits) when the request escapes the
        caller's scope or is internally inconsistent.
        """
        self._check_scope(request, scope)
        if request.expires_at <= now:
            self._deny_issue(request, DenyReason.EXPIRED, "expires_at is in the past")
        if request.max_uses is not None and request.max_uses < 1:
            self._deny_issue(request, DenyReason.MALFORMED, "max_uses must be >= 1")

        tid = uuid.uuid4().hex
        iat = now
        kid, sig = self._keys.sign(
            lambda kid: _canonical_payload(
                tid=tid,
                resource=request.resource,
                operation=str(request.operation),
                exp=request.expires_at,
                max_uses=request.max_uses,
                iat=iat,
                issuer=request.issuer,
                kid=kid,
            )
        )
        self._store.register_issued(tid, request.expires_at)
        self._audit.record(
            "issued",
            token_id=tid,
            resource=request.resource,
            operation=str(request.operation),
            expires_at=request.expires_at,
            max_uses=request.max_uses,
            issuer=request.issuer,
            key_id=kid,
        )
        query = {
            "tid": tid,
            "r": request.resource,
            "op": str(request.operation),
            "exp": str(request.expires_at),
            "mu": "" if request.max_uses is None else str(request.max_uses),
            "iat": str(iat),
            "iss": request.issuer,
            "kid": kid,
            "sig": sig,
        }
        return f"{ACCESS_PATH}?{urlencode(query)}"

    def _check_scope(self, request: IssueRequest, scope: Scope) -> None:
        if request.issuer != scope.identity:
            self._deny_issue(
                request,
                DenyReason.OUT_OF_SCOPE,
                f"issuer {request.issuer!r} is not scope identity {scope.identity!r}",
            )
        if not request.resource.startswith(scope.resource_prefix):
            self._deny_issue(
                request,
                DenyReason.OUT_OF_SCOPE,
                f"resource {request.resource!r} outside prefix {scope.resource_prefix!r}",
            )
        if request.operation not in scope.operations:
            self._deny_issue(
                request,
                DenyReason.OUT_OF_SCOPE,
                f"operation {request.operation} not permitted",
            )

    def _deny_issue(self, request: IssueRequest, reason: DenyReason, detail: str) -> None:
        self._audit.record(
            "issue_denied",
            reason=str(reason),
            detail=detail,
            resource=request.resource,
            operation=str(request.operation),
            issuer=request.issuer,
        )
        raise IssueDenied(reason, detail)

    # ----------------------------------------------------------------- consume

    def consume(
        self,
        token: str,
        resource: str,
        operation: Operation,
        now: int,
        caller: str = "anonymous",
    ) -> ConsumeResult:
        """Verify ``token`` and, if valid, atomically consume one use.

        Never raises for expected denial cases; every outcome is
        returned as a ConsumeResult and written to the audit trail.
        """
        try:
            result = self._consume_inner(token, resource, operation, now)
        except AccessDenied as exc:
            result = ConsumeResult(
                allowed=False,
                reason=str(exc.reason),
                token_id=getattr(exc, "token_id", None),
                uses_after=None,
                remaining=None,
            )
        self._audit.record(
            "consume_allowed" if result.allowed else "consume_denied",
            token_id=result.token_id,
            reason=result.reason,
            resource=resource,
            operation=str(operation),
            caller=caller,
            uses_after=result.uses_after,
        )
        return result

    def consume_url(self, query: str, now: int, caller: str = "anonymous") -> ConsumeResult:
        """Consume a raw presigned URL query string for its embedded grant."""
        try:
            params = self._parse(query)
            resource = params["r"]
            operation = Operation(params["op"])
        except (AccessDenied, ValueError):
            resource, operation = "", Operation.READ
        return self.consume(query, resource, operation, now, caller=caller)

    def _consume_inner(
        self, token: str, resource: str, operation: Operation, now: int
    ) -> ConsumeResult:
        params = self._parse(token)
        tid = params["tid"]
        try:
            return self._verify_and_consume(params, resource, operation, now)
        except AccessDenied as exc:
            exc.token_id = tid
            raise

    def _verify_and_consume(
        self, params: dict[str, str], resource: str, operation: Operation, now: int
    ) -> ConsumeResult:
        tid = params["tid"]
        exp = int(params["exp"])
        iat = int(params["iat"])
        max_uses = None if params["mu"] == "" else int(params["mu"])
        kid = params["kid"]

        # 1. Signature over every constraint parameter, grace-aware.
        payload = _canonical_payload(
            tid=tid,
            resource=params["r"],
            operation=params["op"],
            exp=exp,
            max_uses=max_uses,
            iat=iat,
            issuer=params["iss"],
            kid=kid,
        )
        if not self._keys.verify(kid, payload, params["sig"], now):
            status = self._keys.key_status(kid, now)
            if status == "retired_expired":
                raise AccessDenied(DenyReason.KEY_RETIRED, f"key {kid} past grace")
            raise AccessDenied(DenyReason.BAD_SIGNATURE)

        # 2. Time window, with configurable clock-skew tolerance.
        if now > exp + self._clock_skew:
            raise AccessDenied(DenyReason.EXPIRED)
        if iat - self._clock_skew > now:
            raise AccessDenied(DenyReason.NOT_YET_VALID)

        # 3. Constraint match against the actual request.
        if params["r"] != resource:
            raise AccessDenied(DenyReason.RESOURCE_MISMATCH)
        if params["op"] != str(operation):
            raise AccessDenied(DenyReason.OPERATION_NOT_ALLOWED)

        # 4. Atomic, durable consumption.
        status, uses_after = self._store.try_consume(tid, max_uses)
        if status == CONSUME_UNKNOWN:
            raise AccessDenied(DenyReason.UNKNOWN_TOKEN)
        if status == CONSUME_REVOKED:
            raise AccessDenied(DenyReason.REVOKED)
        if status == CONSUME_EXHAUSTED:
            raise AccessDenied(DenyReason.USAGE_EXHAUSTED)
        assert status == CONSUME_OK
        return ConsumeResult(
            allowed=True,
            reason="ok",
            token_id=tid,
            uses_after=uses_after,
            remaining=None if max_uses is None else max_uses - uses_after,
        )

    # ------------------------------------------------------------------ admin

    def rotate_key(self, new_key_id: str, new_secret: str, now: int) -> str:
        """Rotate the signing key; returns the retired key id."""
        retired = self._keys.rotate(new_key_id, new_secret, now, self._rotation_grace)
        self._audit.record(
            "key_rotated",
            retired_key_id=retired,
            active_key_id=new_key_id,
            grace_until=now + self._rotation_grace,
        )
        return retired

    def revoke(self, token_ids: list[str], now: int, actor: str = "system") -> int:
        """Revoke one or more tokens; returns count newly revoked."""
        newly = self._store.revoke(token_ids, now)
        self._audit.record("revoked", token_ids=token_ids, newly_revoked=newly, actor=actor)
        return newly

    def cleanup(self, now: int) -> int:
        """Remove expired consumption state while keeping tombstones."""
        removed = self._store.cleanup_expired(now)
        self._audit.record("cleanup", removed=removed)
        return removed

    @staticmethod
    def _parse(token: str) -> dict[str, str]:
        query = urlparse(token).query if "://" in token or token.startswith("/") else token
        raw = parse_qs(query, keep_blank_values=True)
        required = ("tid", "r", "op", "exp", "mu", "iat", "iss", "kid", "sig")
        params: dict[str, str] = {}
        for name in required:
            values = raw.get(name)
            if values is None or len(values) != 1:
                raise AccessDenied(DenyReason.MALFORMED, f"missing or duplicate {name}")
            params[name] = values[0]
        # Numeric fields must parse; this also rejects tampered encodings.
        try:
            int(params["exp"])
            int(params["iat"])
            if params["mu"] != "":
                int(params["mu"])
        except ValueError:
            raise AccessDenied(DenyReason.MALFORMED, "non-numeric constraint") from None
        return params
