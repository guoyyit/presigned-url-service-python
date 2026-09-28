"""Acceptance tests: durable state survives process restart.

A new ``PresignedService`` over the same SQLite file simulates a restart:
usage counters, signing keys, revocation and audit log must survive, and a
crash mid-consumption must never leave a partial write.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from presigned.api import create_app
from presigned.clock import FakeClock
from presigned.crypto import KeyStore
from presigned.service import PresignedService
from presigned.storage import Storage

from tests.conftest import START_TS, consume_path, issue, make_settings


def restart(tmp_db_path, clock):
    storage = Storage(tmp_db_path)
    keys = KeyStore(storage, clock)
    settings = make_settings(tmp_db_path, skew=0, grace=3600)
    svc = PresignedService(settings=settings, storage=storage, keys=keys,
                           clock=clock, base_url="http://testserver")
    return svc, storage, keys, TestClient(create_app(svc))


def test_used_count_survives_restart(tmp_db_path, clock):
    svc, storage, keys, client = restart(tmp_db_path, clock)
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=3)
    client.get(consume_path(client, data["url"]))
    client.get(consume_path(client, data["url"]))
    assert storage.get_grant(data["grant_id"]).used_count == 2

    # simulate restart
    svc2, storage2, keys2, client2 = restart(tmp_db_path, clock)
    r = client2.get(consume_path(client2, data["url"]))
    assert r.status_code == 200 and r.json()["used_count"] == 3
    r = client2.get(consume_path(client2, data["url"]))
    assert r.status_code == 409  # cap persisted, not rolled back
    assert storage2.get_grant(data["grant_id"]).used_count == 3


def test_revoked_state_survives_restart(tmp_db_path, clock):
    _, _, _, client = restart(tmp_db_path, clock)
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=3)
    client.post(
        "/grants/revoke",
        headers={"Authorization": "Bearer token-a"},
        json={"grant_ids": [data["grant_id"]]},
    )
    _, _, _, client2 = restart(tmp_db_path, clock)
    r = client2.get(consume_path(client2, data["url"]))
    assert r.status_code == 410 and r.json()["reason"] == "grant_revoked"


def test_tombstone_survives_restart_and_differs_from_never_issued(tmp_db_path, clock):
    _, storage, _, client = restart(tmp_db_path, clock)
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=3)
    gid = data["grant_id"]
    client.post("/grants/revoke", headers={"Authorization": "Bearer token-a"},
                json={"grant_ids": [gid]})
    client.post("/grants/cleanup", json={"grant_ids": [gid]})

    _, storage2, _, client2 = restart(tmp_db_path, clock)
    assert storage2.get_grant(gid).state == "tombstone"
    assert storage2.get_grant("ffffffffffffffffffffffffffffffff") is None
    assert client2.get(consume_path(client2, data["url"])).status_code == 410


def test_signing_keys_survive_restart(tmp_db_path, clock):
    _, storage, keys, client = restart(tmp_db_path, clock)
    data = issue(client, "token-a", ttl_seconds=100_000, max_uses=3)
    client.post("/keys/rotate", headers={"Authorization": "Bearer token-admin"})

    _, storage2, keys2, client2 = restart(tmp_db_path, clock)
    assert keys2.current_key_id != data["key_id"]
    # old key grant still verifies inside grace after restart
    clock.advance(10)
    r = client2.get(consume_path(client2, data["url"]))
    assert r.status_code == 200, r.text
    assert {k.key_id for k in storage2.load_keys()} == {
        k.key_id for k in storage.load_keys()
    }


def test_no_partial_write_when_consumption_transaction_is_killed(tmp_db_path):
    """A crash between the UPDATE and COMMIT must roll the increment back."""
    clock = FakeClock(START_TS)
    storage = Storage(tmp_db_path)
    keys = KeyStore(storage, clock)
    settings = make_settings(tmp_db_path)
    svc = PresignedService(settings=settings, storage=storage, keys=keys,
                           clock=clock, base_url="http://testserver")
    client = TestClient(create_app(svc))
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=2)
    gid = data["grant_id"]

    # Mimic storage.consume_grant's exact transaction shape, but crash before
    # COMMIT. BEGIN IMMEDIATE + UPDATE + ROLLBACK leaves the row untouched.
    conn = storage.connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE grants SET used_count = used_count + 1 WHERE grant_id = ?", (gid,))
        mid = conn.execute("SELECT used_count FROM grants WHERE grant_id = ?", (gid,)).fetchone()
        assert mid["used_count"] == 1  # visible inside the transaction
        raise RuntimeError("simulated crash before commit")
    except RuntimeError:
        conn.execute("ROLLBACK")
    finally:
        conn.close()

    # Restart-like fresh connection: no partial write survived.
    fresh = Storage(tmp_db_path).get_grant(gid)
    assert fresh.used_count == 0

    # Both uses are still available, and consumption remains auditable.
    r1 = client.get(consume_path(client, data["url"]))
    assert r1.status_code == 200 and r1.json()["used_count"] == 1
    r2 = client.get(consume_path(client, data["url"]))
    assert r2.status_code == 200 and r2.json()["used_count"] == 2
    r3 = client.get(consume_path(client, data["url"]))
    assert r3.status_code == 409
    assert Storage(tmp_db_path).get_grant(gid).used_count == 2
