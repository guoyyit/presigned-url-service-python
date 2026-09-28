"""Acceptance tests: caller scopes on issuance and bound consumers."""

from __future__ import annotations

from tests.conftest import consume_path, issue


def test_missing_or_invalid_token_is_rejected(client):
    body = {"resource_path": "/data/a/x", "operation": "read", "ttl_seconds": 10}
    assert client.post("/grants", json=body).status_code == 401
    assert client.post("/grants", headers={"Authorization": "Bearer nope"},
                       json=body).status_code == 401


def test_caller_cannot_issue_outside_path_prefix(client):
    r = client.post(
        "/grants",
        headers={"Authorization": "Bearer token-a"},
        json={"resource_path": "/data/b/secret", "operation": "read",
              "ttl_seconds": 10, "max_uses": 1},
    )
    assert r.status_code == 403 and r.json()["error"] == "scope_denied"


def test_caller_cannot_issue_unauthorized_operation(client):
    r = client.post(
        "/grants",
        headers={"Authorization": "Bearer token-a"},
        json={"resource_path": "/data/a/x", "operation": "write",
              "ttl_seconds": 10, "max_uses": 1},
    )
    assert r.status_code == 403 and r.json()["error"] == "scope_denied"


def test_cannot_revoke_another_callers_grant(client):
    data = issue(client, "token-b", resource_path="/data/b/x", operation="read")
    r = client.post(
        "/grants/revoke",
        headers={"Authorization": "Bearer token-a"},
        json={"grant_ids": [data["grant_id"]]},
    )
    assert r.status_code == 200 and r.json()["denied"] == [data["grant_id"]]
    # the foreign grant still works
    assert client.get(consume_path(client, data["url"])).status_code == 200


def test_consumer_binding_enforced_on_consume(client):
    data = issue(client, "token-admin", resource_path="/data/a/x",
                 operation="read", max_uses=3, consumer="partner-1")
    url_path = consume_path(client, data["url"])
    # no identity presented -> denied
    assert client.get(url_path).status_code == 403
    # wrong identity -> denied
    assert client.get(url_path, headers={"X-Consumer": "partner-2"}).status_code == 403
    # bound identity -> allowed
    ok = client.get(url_path, headers={"X-Consumer": "partner-1"})
    assert ok.status_code == 200


def test_scope_denied_issuance_is_audited(client):
    client.post(
        "/grants",
        headers={"Authorization": "Bearer token-a"},
        json={"resource_path": "/data/b/secret", "operation": "read",
              "ttl_seconds": 10},
    )
    events = client.get("/audit", headers={"Authorization": "Bearer token-admin"}
                        ).json()["events"]
    denied = [e for e in events if e["event_type"] == "issue" and e["result"] == "denied"]
    assert denied and denied[0]["reason"] == "outside_caller_scope"
    assert denied[0]["resource_path"] == "/data/b/secret"


def test_tampered_url_cannot_reach_other_resource(client):
    data = issue(client, "token-a", resource_path="/data/a/public",
                 operation="read", max_uses=2)
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(data["url"])
    q = dict(parse_qsl(parts.query))
    q["p"] = "/data/a/public"
    # re-point path claim without signature -> rejected
    q["p"] = "/data/a/private"
    bad = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
    r = client.get(bad.replace("http://testserver", ""))
    assert r.status_code == 403 and r.json()["reason"] == "invalid_signature"
