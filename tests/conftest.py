"""Shared fixtures for presigned-url acceptance tests."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from presigned.api import create_app
from presigned.clock import FakeClock
from presigned.config import CallerScope, Settings
from presigned.crypto import KeyStore
from presigned.service import PresignedService
from presigned.storage import Storage

START_TS = 1_750_000_000  # fixed "now" for deterministic acceptance tests


@pytest.fixture
def tmp_db_path():
    with tempfile.TemporaryDirectory() as d:
        yield os.path.join(d, "presigned.db")


def make_settings(db_path: str, *, skew: int = 0, grace: int = 3600) -> Settings:
    return Settings(
        database_path=db_path,
        clock_skew_seconds=skew,
        key_grace_period_seconds=grace,
        sign_alg="HMAC-SHA256",
        base_url="http://testserver",
        callers=(
            CallerScope("team-a", ("/data/a/",), ("read",), "token-a"),
            CallerScope("team-b", ("/data/b/",), ("read", "write"), "token-b"),
            CallerScope("admin", ("/",), ("read", "write", "delete"), "token-admin"),
        ),
    )


@pytest.fixture
def clock():
    return FakeClock(START_TS)


@pytest.fixture
def storage(tmp_db_path):
    return Storage(tmp_db_path)


@pytest.fixture
def settings(tmp_db_path):
    return make_settings(tmp_db_path)


@pytest.fixture
def keys(storage, clock):
    return KeyStore(storage, clock)


@pytest.fixture
def service(settings, storage, keys, clock):
    return PresignedService(
        settings=settings,
        storage=storage,
        keys=keys,
        clock=clock,
        base_url="http://testserver",
    )


@pytest.fixture
def client(service):
    return TestClient(create_app(service))


@pytest.fixture
def tmp_db_path_factory():
    """Return a fresh db path on demand inside one temp dir (restart tests)."""
    with tempfile.TemporaryDirectory() as d:
        yield lambda: os.path.join(d, "presigned.db")


def issue(client: TestClient, token: str, **overrides) -> dict:
    body = {
        "resource_path": "/data/a/file",
        "operation": "read",
        "ttl_seconds": 60,
        "max_uses": 1,
    }
    body.update(overrides)
    r = client.post("/grants", headers={"Authorization": f"Bearer {token}"}, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def consume_path(client: TestClient, url: str, **kw) -> str:
    return url.replace("http://testserver", "")
