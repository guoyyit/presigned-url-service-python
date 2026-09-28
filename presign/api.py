"""HTTP surface: issue, access, consume, revoke, rotate, and health.

The service instance is provided through FastAPI dependency injection
so tests and local acceptance runs can substitute their own (e.g. with
a temp database) without touching globals.
"""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .errors import IssueDenied
from .models import ConsumeResult, IssueRequest, Operation
from .service import PresignService

router = APIRouter(prefix="/presign", tags=["presign"])


def get_service() -> PresignService:  # pragma: overridden in app wiring/tests
    raise RuntimeError("PresignService dependency not wired")


Service = Annotated[PresignService, Depends(get_service)]
Caller = Annotated[str, Header(alias="X-Caller-Id")]


def _now() -> int:
    return int(time.time())


class IssueBody(BaseModel):
    resource: str
    operation: Operation = Operation.READ
    expires_at: int = Field(description="unix seconds")
    max_uses: int | None = None


class ConsumeBody(BaseModel):
    token: str
    resource: str
    operation: Operation = Operation.READ


class RevokeBody(BaseModel):
    token_ids: list[str]


class RotateBody(BaseModel):
    new_key_id: str
    new_secret: str


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/issue", status_code=201)
def issue(body: IssueBody, service: Service, x_caller_id: Caller = "anonymous") -> dict[str, str]:
    scope = service.scope_for(x_caller_id)
    if scope is None:
        raise HTTPException(status_code=403, detail="unknown caller identity")
    try:
        url = service.issue(
            IssueRequest(
                resource=body.resource,
                operation=body.operation,
                expires_at=body.expires_at,
                max_uses=body.max_uses,
                issuer=x_caller_id,
            ),
            scope,
            _now(),
        )
    except IssueDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc.reason)) from exc
    return {"url": url}


@router.get("/access")
def access(request: Request, service: Service, x_caller_id: Caller = "anonymous") -> dict[str, object]:
    """The presigned URL itself: consumes one use for the embedded grant."""
    result = service.consume_url(request.url.query, _now(), caller=x_caller_id)
    return _result_payload(result)


@router.post("/consume")
def consume(body: ConsumeBody, service: Service, x_caller_id: Caller = "anonymous") -> dict[str, object]:
    """Explicit verification: state the resource/operation being attempted."""
    result = service.consume(
        body.token, body.resource, body.operation, _now(), caller=x_caller_id
    )
    return _result_payload(result)


@router.post("/revoke")
def revoke(body: RevokeBody, service: Service, x_caller_id: Caller = "anonymous") -> dict[str, int]:
    newly = service.revoke(body.token_ids, _now(), actor=x_caller_id)
    return {"revoked": newly}


@router.post("/rotate")
def rotate(body: RotateBody, service: Service, x_caller_id: Caller = "anonymous") -> dict[str, str]:
    retired = service.rotate_key(body.new_key_id, body.new_secret, _now())
    return {"retired": retired}


def _result_payload(result: ConsumeResult) -> dict[str, object]:
    return {
        "allowed": result.allowed,
        "reason": result.reason,
        "token_id": result.token_id,
        "uses_after": result.uses_after,
        "remaining": result.remaining,
    }
