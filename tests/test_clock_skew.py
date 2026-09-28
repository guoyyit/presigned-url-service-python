"""Acceptance tests: clock-skew tolerance and parameter tampering."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest

from tests.conftest import START_TS, consume_path, issue, make_settings
from presigned.api import create_app
from presigned.clock import FakeClock
from presigned.crypto import KeyStore
from presigned.service import PresignedService
from presigned.storage import Storage


@pytest.fixture
def skew_client(tmp_db_path, clock):
    settings = make_settings(tmp_db_path, skew=30, grace=3600)
    storage = Storage(tmp_db_path)
    keys = KeyStore(storage, clock)
    svc = PresignedService(settings=settings, storage=storage, keys=keys,
                           clock=clock, base_url="http://testserver")
    from fastapi.testclient import TestClient
    return TestClient(create_app(svc))


def tamper(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query))
    q[key] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))


def test_request_within_skew_window_is_allowed(skew_client, clock):
    data = issue(skew_client, "token-a", ttl_seconds=60, max_uses=5)
    # consumer/server clock 30s fast relative to real expiry -> tolerated
    clock.set(START_TS + 90)
    r = skew_client.get(consume_path(skew_client, data["url"]))
    assert r.status_code == 200, r.text


def test_request_outside_skew_window_is_rejected(skew_client, clock):
    data = issue(skew_client, "token-a", ttl_seconds=60, max_uses=5)
    clock.set(START_TS + 91)
    r = skew_client.get(consume_path(skew_client, data["url"]))
    assert r.status_code == 410
    assert r.json()["reason"] == "grant_expired"


def test_zero_skew_rejects_even_one_second_late(client, clock):
    data = issue(client, "token-a", ttl_seconds=60, max_uses=5)
    clock.set(START_TS + 61)
    r = client.get(consume_path(client, data["url"]))
    assert r.status_code == 410


@pytest.mark.parametrize(
    "param,value",
    [
        ("p", "/data/a/evil"),
        ("op", "write"),
        ("exp", "9999999999"),
        ("n", "99"),
        ("iat", "1"),
        ("kid", "k0000000000000"),
    ],
)
def test_any_tampered_parameter_is_rejected(client, param, value):
    data = issue(client, "token-a", ttl_seconds=60, max_uses=5)
    bad = tamper(data["url"], param, value).replace("http://testserver", "")
    r = client.get(bad)
    assert r.status_code == 403
    assert r.json()["granted"] is False
    assert r.json()["reason"] == "invalid_signature"


def test_tampered_signature_is_rejected(client):
    data = issue(client, "token-a", ttl_seconds=60, max_uses=5)
    bad = tamper(data["url"], "sig", "ab" * 32).replace("http://testserver", "")
    r = client.get(bad)
    assert r.status_code == 403 and r.json()["reason"] == "invalid_signature"


def test_replay_after_real_expiry_with_skew_still_rejected(skew_client, clock):
    data = issue(skew_client, "token-a", ttl_seconds=10, max_uses=5)
    clock.set(START_TS + 41)  # exp + skew = 40
    r = skew_client.get(consume_path(skew_client, data["url"]))
    assert r.status_code == 410 and r.json()["reason"] == "grant_expired"
