"""Acceptance tests: expiry and replay of expired presigned URLs."""

from __future__ import annotations

from tests.conftest import START_TS, consume_path, issue


def test_grant_is_consumable_before_expiry(client):
    data = issue(client, "token-a", ttl_seconds=60, max_uses=5)
    r = client.get(consume_path(client, data["url"]))
    assert r.status_code == 200
    assert r.json()["granted"] is True


def test_grant_expires_at_ttl_boundary_without_skew(client, clock):
    data = issue(client, "token-a", ttl_seconds=60, max_uses=5)
    clock.set(START_TS + 60)
    r = client.get(consume_path(client, data["url"]))
    assert r.status_code == 200, r.text  # expires_at inclusive

    clock.set(START_TS + 61)
    r = client.get(consume_path(client, data["url"]))
    assert r.status_code == 410
    assert r.json()["reason"] == "grant_expired"


def test_expired_grant_cannot_be_replayed(client, clock):
    data = issue(client, "token-a", ttl_seconds=10, max_uses=100)
    clock.set(START_TS + 11)
    for _ in range(3):
        r = client.get(consume_path(client, data["url"]))
        assert r.status_code == 410
        assert r.json()["reason"] == "grant_expired"
    # used count never advanced after expiry
    status = client.get(
        f"/grants/{data['grant_id']}", headers={"Authorization": "Bearer token-admin"}
    ).json()
    assert status["used_count"] == 0


def test_consume_of_unknown_grant_id_is_not_found(client):
    forged = (
        "/consume?kid=kdead&gid=deadbeef&p=%2Fx&op=read&exp=9999999999"
        "&n=1&iat=1&alg=HMAC-SHA256&sig=" + "0" * 64
    )
    r = client.get(forged)
    assert r.status_code in (403, 404)
    assert r.json()["granted"] is False


def test_expiry_is_audited(client, clock):
    data = issue(client, "token-a", ttl_seconds=10, max_uses=1)
    clock.set(START_TS + 11)
    client.get(consume_path(client, data["url"]))
    audit = client.get(
        "/audit",
        params={"grant_id": data["grant_id"]},
        headers={"Authorization": "Bearer token-admin"},
    ).json()["events"]
    denied = [e for e in audit if e["result"] == "denied"]
    assert denied and denied[0]["reason"] == "grant_expired"
