"""HTTP layer exposing the presigned-url service.

Endpoints
---------
POST /grants                 issue a presigned URL (token auth, scope checked)
ALL  /consume                consume one use (public URL; signature is the proof)
POST /grants/revoke          revoke one or a batch of grants (issuer only)
POST /grants/cleanup         turn revoked grants into tombstines
GET  /grants/{grant_id}      inspect state incl. never_issued vs tombstone
POST /keys/rotate            rotate the signing key
GET  /audit                  inspect audit events (token auth)
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from presigned.errors import PresignedError
from presigned.service import PresignedService

_DENIED_STATUS = {
    "invalid_request": 400,
    "scope_denied": 403,
    "invalid_signature": 403,
    "grant_expired": 410,
    "grant_revoked": 410,
    "grant_not_found": 404,
    "usage_exhausted": 409,
    "constraint_violation": 403,
    "storage_error": 500,
}


class IssueRequest(BaseModel):
    resource_path: str = Field(min_length=1)
    operation: str
    ttl_seconds: int = Field(gt=0)
    max_uses: int | None = Field(default=None, ge=1)
    consumer: str | None = None


class RevokeRequest(BaseModel):
    grant_ids: list[str] = Field(min_length=1)


class CleanupRequest(BaseModel):
    grant_ids: list[str] = Field(min_length=1)


def create_app(service: PresignedService) -> FastAPI:
    app = FastAPI(title="Presigned Temporary Access Service", version="0.1.0")
    app.state.service = service

    def require_caller(
        authorization: str | None = Header(default=None),
        x_caller_token: str | None = Header(default=None),
    ):
        token = x_caller_token
        if not token and authorization:
            if authorization.lower().startswith("bearer "):
                token = authorization[7:].strip()
        if not token:
            raise HTTPException(status_code=401, detail="missing bearer token")
        scope = service.settings.scope_for_token(token)
        if scope is None:
            raise HTTPException(status_code=401, detail="invalid token")
        return scope

    @app.exception_handler(PresignedError)
    async def handle_domain_error(_: Request, exc: PresignedError) -> JSONResponse:
        status = _DENIED_STATUS.get(exc.code, 400)
        return JSONResponse(
            status_code=status,
            content={
                "error": exc.code,
                "message": exc.message,
                "grant_id": exc.grant_id,
            },
        )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/grants", status_code=201)
    def issue_grant(body: IssueRequest, caller=Depends(require_caller)) -> dict:
        signed = service.issue(
            caller_id=caller.caller_id,
            resource_path=body.resource_path,
            operation=body.operation,
            ttl_seconds=body.ttl_seconds,
            max_uses=body.max_uses,
            consumer=body.consumer,
        )
        return {
            "url": signed.url,
            "grant_id": signed.grant_id,
            "resource_path": signed.resource_path,
            "operation": signed.operation,
            "expires_at": signed.expires_at,
            "max_uses": signed.max_uses,
            "issued_at": signed.issued_at,
            "key_id": signed.key_id,
        }

    @app.api_route("/consume", methods=["GET", "POST"])
    async def consume(request: Request, x_consumer: str | None = Header(default=None)):
        # The signature + constraints live entirely in the query string.
        raw_url = str(request.url)
        consumer = x_consumer
        result = service.consume_url(raw_url, consumer=consumer)
        if result.granted:
            return {
                "granted": True,
                "grant_id": result.grant_id,
                "used_count": result.used_count,
                "max_uses": result.max_uses,
            }
        status = 403
        if result.reason in ("grant_expired", "grant_revoked"):
            status = 410
        elif result.reason == "grant_not_found":
            status = 404
        elif result.reason == "usage_exhausted":
            status = 409
        return JSONResponse(
            status_code=status,
            content={"granted": False, "grant_id": result.grant_id, "reason": result.reason},
        )

    @app.post("/grants/revoke")
    def revoke_grants(body: RevokeRequest, caller=Depends(require_caller)) -> dict:
        return service.revoke(caller.caller_id, body.grant_ids)

    @app.post("/grants/cleanup")
    def cleanup_grants(body: CleanupRequest) -> dict:
        return service.cleanup(body.grant_ids)

    @app.get("/grants/{grant_id}")
    def grant_status(grant_id: str, caller=Depends(require_caller)) -> dict:
        return service.grant_status(grant_id)

    @app.post("/keys/rotate")
    def rotate_keys(caller=Depends(require_caller)) -> dict:
        return service.rotate_keys()

    @app.get("/audit")
    def list_audit(
        grant_id: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
        caller=Depends(require_caller),
    ) -> dict:
        events = service.audit(grant_id=grant_id, limit=limit)
        return {
            "events": [
                {
                    "id": e.id,
                    "event_time": e.event_time,
                    "event_type": e.event_type,
                    "grant_id": e.grant_id,
                    "caller_id": e.caller_id,
                    "resource_path": e.resource_path,
                    "operation": e.operation,
                    "result": e.result,
                    "reason": e.reason,
                    "detail": e.detail,
                }
                for e in events
            ]
        }

    return app
