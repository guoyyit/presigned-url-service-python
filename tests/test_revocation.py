"""Acceptance tests: single and batch revocation, cleanup and auditability."""

from __future__ import annotations

from tests.conftest import consume_path, issue


def test_revoked_single_grant_is_denied_even_while_valid(client):
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=5)
    r = client.post(
        "/grants/revoke",
        headers={"Authorization": "Bearer token-a"},
        json={"grant_ids": [data["grant_id"]]},
    )
    assert r.status_code == 200
    assert r.json()["revoked"] == [data["grant_id"]]

    cr = client.get(consume_path(client, data["url"]))
    assert cr.status_code == 410
    assert cr.json()["reason"] == "grant_revoked"


def test_revoke_is_idempotent(client):
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=5)
    hdr = {"Authorization": "Bearer token-a"}
    body = {"grant_ids": [data["grant_id"]]}
    first = client.post("/grants/revoke", headers=hdr, json=body).json()
    second = client.post("/grants/revoke", headers=hdr, json=body).json()
    assert first["revoked"] == [data["grant_id"]]
    assert second["revoked"] == []
    assert second["already_revoked"] == [data["grant_id"]]


def test_batch_revoke_mixes_existing_unknown_and_foreign(client):
    own1 = issue(client, "token-a", ttl_seconds=3600, max_uses=2)["grant_id"]
    own2 = issue(client, "token-a", ttl_seconds=3600, max_uses=2,
                 resource_path="/data/a/second")["grant_id"]
    foreign = issue(client, "token-b", ttl_seconds=3600, max_uses=2,
                    resource_path="/data/b/x")["grant_id"]
    missing = "0123456789abcdef0123456789abcdef"

    r = client.post(
        "/grants/revoke",
        headers={"Authorization": "Bearer token-a"},
        json={"grant_ids": [own1, own2, foreign, missing]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert sorted(body["revoked"]) == sorted([own1, own2])
    assert body["denied"] == [foreign]
    assert body["not_found"] == [missing]
    assert body["batch_id"].startswith("batch-")


def test_revoked_grant_consume_is_audited(client):
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=5)
    client.post("/grants/revoke", headers={"Authorization": "Bearer token-a"},
                json={"grant_ids": [data["grant_id"]]})
    client.get(consume_path(client, data["url"]))
    events = client.get(
        "/audit", params={"grant_id": data["grant_id"]},
        headers={"Authorization": "Bearer token-admin"},
    ).json()["events"]
    assert any(e["event_type"] == "revoke" and e["result"] == "success" for e in events)
    assert any(e["event_type"] == "consume" and e["reason"] == "grant_revoked"
               for e in events)


def test_cleanup_keeps_tombstone_distinguishable_from_never_issued(client):
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=5)
    gid = data["grant_id"]
    client.post("/grants/revoke", headers={"Authorization": "Bearer token-a"},
                json={"grant_ids": [gid]})
    cleaned = client.post("/grants/cleanup", json={"grant_ids": [gid]})
    assert cleaned.status_code == 200
    assert cleaned.json()["cleaned"] == [gid]

    hdr = {"Authorization": "Bearer token-admin"}
    tombstoned = client.get(f"/grants/{gid}", headers=hdr).json()
    assert tombstoned["exists"] is True and tombstoned["state"] == "tombstone"
    unknown = client.get("/grants/0123456789abcdef0123456789abcdef", headers=hdr).json()
    assert unknown["exists"] is False and unknown["state"] == "never_issued"

    # The cleaned URL must remain unusable.
    assert client.get(consume_path(client, data["url"])).status_code == 410
    # Cleaning an active or unknown grant changes nothing.
    active = issue(client, "token-a", ttl_seconds=3600, max_uses=2,
                   resource_path="/data/a/keep")
    res = client.post("/grants/cleanup", json={"grant_ids": [active["grant_id"]]}).json()
    assert res["cleaned"] == []


def test_revoke_does_not_refund_or_lose_usage_history(client):
    data = issue(client, "token-a", ttl_seconds=3600, max_uses=3)
    client.get(consume_path(client, data["url"]))
    client.post("/grants/revoke", headers={"Authorization": "Bearer token-a"},
                json={"grant_ids": [data["grant_id"]]})
    status = client.get(
        f"/grants/{data['grant_id']}", headers={"Authorization": "Bearer token-admin"}
    ).json()
    assert status["state"] == "revoked" and status["used_count"] == 1
