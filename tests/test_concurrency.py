"""Acceptance tests: concurrent consumption must never exceed the cap."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
from concurrent.futures import ThreadPoolExecutor

from tests.conftest import consume_path, issue


def test_concurrent_threads_never_exceed_cap(client):
    data = issue(client, "token-a", ttl_seconds=300, max_uses=10)
    path = consume_path(client, data["url"])

    def hit(_):
        r = client.get(path)
        return r.status_code, r.json()

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(hit, range(60)))

    granted = [ok for ok, body in results if body.get("granted")]
    assert len(granted) == 10
    denied = [body for ok, body in results if not body.get("granted")]
    assert len(denied) == 50
    assert {b["reason"] for b in denied} == {"usage_exhausted"}
    # every request got a deterministic answer
    assert all(ok in (200, 409) for ok, _ in results)


def test_single_use_grant_has_exactly_one_winner(client):
    data = issue(client, "token-a", ttl_seconds=300, max_uses=1)
    path = consume_path(client, data["url"])
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: client.get(path), range(32)))
    winners = [r for r in results if r.json().get("granted")]
    assert len(winners) == 1
    assert winners[0].json()["used_count"] == 1
    losers = [r for r in results if not r.json().get("granted")]
    assert all(r.json()["reason"] == "usage_exhausted" for r in losers)


def test_concurrent_consumption_across_processes(tmp_db_path):
    """Real OS processes sharing one SQLite file must also respect the cap."""
    script = textwrap.dedent(
        f'''
        import os, json, sys
        os.environ["PRESIGNED_DB_PATH"] = {tmp_db_path!r}
        from main import app
        from fastapi.testclient import TestClient
        c = TestClient(app)
        r = c.get(sys.argv[1])
        print(json.dumps({{"status": r.status_code, "body": r.json()}}))
        '''
    )
    # Seed a grant in the shared database with the real (deterministic-ish) path.
    os.environ["PRESIGNED_DB_PATH"] = tmp_db_path
    sys.path.insert(0, os.getcwd())
    import importlib

    import main as main_module

    importlib.reload(main_module)
    seeder = main_module.app
    from fastapi.testclient import TestClient

    seed_client = TestClient(seeder)
    r = seed_client.post(
        "/grants",
        headers={"Authorization": "Bearer dev-token"},
        json={
            "resource_path": "/data/a/shared",
            "operation": "read",
            "ttl_seconds": 3600,
            "max_uses": 5,
        },
    )
    assert r.status_code == 201, r.text
    url_path = r.json()["url"].replace("http://localhost:8000", "")

    env = dict(os.environ, PRESIGNED_DB_PATH=tmp_db_path)
    procs = [
        subprocess.run(
            [sys.executable, "-c", script, url_path],
            capture_output=True, text=True, env=env,
        )
        for _ in range(20)
    ]
    outcomes = []
    for p in procs:
        assert p.returncode == 0, p.stderr
        import json

        outcomes.append(json.loads(p.stdout.strip()))
    wins = [o for o in outcomes if o["body"].get("granted")]
    assert len(wins) == 5, outcomes
    assert all(o["body"]["reason"] == "usage_exhausted" for o in outcomes if not o["body"].get("granted"))


def test_every_decision_is_audited(client):
    data = issue(client, "token-a", ttl_seconds=300, max_uses=2)
    path = consume_path(client, data["url"])
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: client.get(path), range(8)))
    audit = client.get(
        "/audit",
        params={"grant_id": data["grant_id"]},
        headers={"Authorization": "Bearer token-admin"},
    ).json()["events"]
    consume_events = [e for e in audit if e["event_type"] == "consume"]
    assert len(consume_events) == 8  # 2 success + 6 deterministic denials
