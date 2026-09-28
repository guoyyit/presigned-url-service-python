"""End-to-end HTTP tests through the FastAPI surface."""

import os
import time

import pytest
from fastapi.testclient import TestClient

from presign.api import get_service, router
from presign.audit import AuditLogger
from presign.models import Operation, Scope
from presign.service import PresignService
from presign.signing import KeyStore
from presign.store import StateStore


@pytest.fixture()
def client(tmp_path):
    from fastapi import FastAPI

    service = PresignService(
        keys=KeyStore("k1", {"k1": "secret-one"}),
        store=StateStore(os.path.join(tmp_path, "state.db")),
        audit=AuditLogger(os.path.join(tmp_path, "audit.log")),
        scopes={"alice": Scope("alice", "docs/", frozenset({Operation.READ}))},
    )
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: service
    with TestClient(app) as c:
        c.service = service
        yield c


def _issue(client, resource="docs/a.txt", max_uses=None, caller="alice"):
    body = {
        "resource": resource,
        "operation": "read",
        "expires_at": int(time.time()) + 600,
    }
    if max_uses is not None:
        body["max_uses"] = max_uses
    resp = client.post("/presign/issue", json=body, headers={"X-Caller-Id": caller})
    assert resp.status_code == 201, resp.text
    return resp.json()["url"]


def test_health(client):
    assert client.get("/presign/health").json() == {"status": "ok"}


def test_issue_and_access_roundtrip(client):
    url = _issue(client, max_uses=1)
    ok = client.get(url)
    assert ok.status_code == 200 and ok.json()["allowed"] is True
    replay = client.get(url)
    assert replay.json()["allowed"] is False
    assert replay.json()["reason"] == "usage_exhausted"


def test_issue_forbidden_for_unknown_caller(client):
    resp = client.post(
        "/presign/issue",
        json={"resource": "docs/a", "operation": "read",
              "expires_at": int(time.time()) + 60},
        headers={"X-Caller-Id": "mallory"},
    )
    assert resp.status_code == 403


def test_issue_forbidden_outside_prefix(client):
    resp = client.post(
        "/presign/issue",
        json={"resource": "etc/shadow", "operation": "read",
              "expires_at": int(time.time()) + 60},
        headers={"X-Caller-Id": "alice"},
    )
    assert resp.status_code == 403


def test_consume_endpoint_checks_stated_resource(client):
    url = _issue(client)
    resp = client.post("/presign/consume", json={
        "token": url, "resource": "docs/a.txt", "operation": "read",
    })
    assert resp.json()["allowed"] is True
    resp = client.post("/presign/consume", json={
        "token": url, "resource": "docs/other.txt", "operation": "read",
    })
    assert resp.json()["allowed"] is False
    assert resp.json()["reason"] == "resource_mismatch"


def test_revoke_endpoint(client):
    url = _issue(client)
    from urllib.parse import parse_qs, urlparse

    tid = parse_qs(urlparse(url).query)["tid"][0]
    resp = client.post("/presign/revoke", json={"token_ids": [tid]},
                       headers={"X-Caller-Id": "alice"})
    assert resp.json() == {"revoked": 1}
    assert client.get(url).json()["reason"] == "revoked"


def test_rotate_endpoint(client):
    resp = client.post("/presign/rotate",
                       json={"new_key_id": "k2", "new_secret": "s2"},
                       headers={"X-Caller-Id": "alice"})
    assert resp.json() == {"retired": "k1"}
    url = _issue(client)
    assert "kid=k2" in url
    assert client.get(url).json()["allowed"] is True
