"""Acceptance tests: signing-key rotation and the configurable grace period."""

from __future__ import annotations

from tests.conftest import consume_path, issue


def test_grant_signed_by_current_key_consumes_fine(client):
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=3)
    r = client.get(consume_path(client, data["url"]))
    assert r.status_code == 200


def test_old_key_grant_still_valid_within_grace_period(client, clock):
    data = issue(client, "token-a", ttl_seconds=10_000, max_uses=5)
    rot = client.post("/keys/rotate", headers={"Authorization": "Bearer token-admin"})
    assert rot.status_code == 200
    # 3600s grace (default fixture)
    clock.advance(3599)
    r = client.get(consume_path(client, data["url"]))
    assert r.status_code == 200, r.text


def test_old_key_grant_fails_after_grace_period(client, clock):
    data = issue(client, "token-a", ttl_seconds=100_000, max_uses=5)
    client.post("/keys/rotate", headers={"Authorization": "Bearer token-admin"})
    clock.advance(3601)
    r = client.get(consume_path(client, data["url"]))
    assert r.status_code == 403
    assert r.json()["reason"] == "invalid_signature"


def test_new_grants_after_rotation_use_new_key(client):
    before = issue(client, "token-a", ttl_seconds=3600, max_uses=3)
    rot = client.post("/keys/rotate", headers={"Authorization": "Bearer token-admin"}).json()
    after = issue(client, "token-a", ttl_seconds=3600, max_uses=3)
    assert before["key_id"] == rot["old_key_id"]
    assert after["key_id"] == rot["new_key_id"]
    r = client.get(consume_path(client, after["url"]))
    assert r.status_code == 200


def test_zero_grace_period_rejects_old_key_immediately(tmp_db_path, clock):
    from fastapi.testclient import TestClient

    from presigned.api import create_app
    from presigned.crypto import KeyStore
    from presigned.service import PresignedService
    from presigned.storage import Storage

    from tests.conftest import make_settings

    settings = make_settings(tmp_db_path, skew=0, grace=0)
    storage = Storage(tmp_db_path)
    keys = KeyStore(storage, clock)
    svc = PresignedService(settings=settings, storage=storage, keys=keys,
                           clock=clock, base_url="http://testserver")
    c = TestClient(create_app(svc))
    data = issue(c, "token-a", ttl_seconds=3600, max_uses=3)
    c.post("/keys/rotate", headers={"Authorization": "Bearer token-admin"})
    r = c.get(data["url"].replace("http://testserver", ""))
    assert r.status_code == 403 and r.json()["reason"] == "invalid_signature"


def test_concurrent_rotations_keep_one_consistent_current_key(tmp_db_path, clock):
    from concurrent.futures import ThreadPoolExecutor

    from fastapi.testclient import TestClient

    from presigned.api import create_app
    from presigned.crypto import KeyStore
    from presigned.service import PresignedService
    from presigned.storage import Storage

    from tests.conftest import make_settings

    storage = Storage(tmp_db_path)
    keys = KeyStore(storage, clock)
    svc = PresignedService(
        settings=make_settings(tmp_db_path, grace=100_000),
        storage=storage, keys=keys, clock=clock, base_url="http://testserver",
    )
    c = TestClient(create_app(svc))
    data = issue(c, "token-a", ttl_seconds=10_000_000, max_uses=100)
    original_id = data["key_id"]

    def rotate(_):
        return c.post("/keys/rotate", headers={"Authorization": "Bearer token-admin"}).json()

    with ThreadPoolExecutor(max_workers=8) as pool:
        rotations = list(pool.map(rotate, range(8)))

    # Exactly one new key per rotation, and ids are all distinct.
    new_ids = [r_["new_key_id"] for r_ in rotations]
    old_ids = {r_["old_key_id"] for r_ in rotations}
    assert len(set(new_ids)) == 8
    assert original_id in old_ids  # the first rotation retired the original
    # Persistence is consistent regardless of completion order.
    persisted = storage.load_keys()
    assert len(persisted) == 9
    currents = [k for k in persisted if k.rotated_at is None]
    assert len(currents) == 1
    assert currents[0].key_id == keys.current_key_id
    assert currents[0].key_id in new_ids
    # Rotations form one linear chain ordered by rotation timestamp.
    rotated = sorted((k for k in persisted if k.rotated_at is not None),
                     key=lambda k: k.rotated_at)
    assert len(rotated) == 8
    # newest persisted key is the current one
    assert max(k.created_at for k in persisted) == currents[0].created_at
    # After the whole grace window ends, the oldest grant fails clearly.
    clock.advance(100_001)
    r = c.get(data["url"].replace("http://testserver", ""))
    assert r.status_code == 403 and r.json()["reason"] == "invalid_signature"
