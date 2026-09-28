#!/usr/bin/env python3
"""Reproducible local acceptance walkthrough for the presigned URL service.

It runs entirely against an isolated temporary SQLite database and a
:class:`FakeClock`, so expiry, clock skew, key-rotation grace windows and
restart recovery can all be demonstrated deterministically in seconds.

Run:  uv run python scripts/acceptance_demo.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from presigned.api import create_app
from presigned.clock import FakeClock
from presigned.config import CallerScope, Settings
from presigned.crypto import KeyStore
from presigned.service import PresignedService
from presigned.storage import Storage

BASE = "http://testserver"
T0 = 1_750_000_000


def settings_for(db: str, *, skew: int = 0, grace: int = 3600) -> Settings:
    return Settings(
        database_path=db,
        clock_skew_seconds=skew,
        key_grace_period_seconds=grace,
        sign_alg="HMAC-SHA256",
        base_url=BASE,
        callers=(
            CallerScope("team-a", ("/data/a/",), ("read",), "token-a"),
            CallerScope("admin", ("/",), ("read", "write", "delete"), "token-admin"),
        ),
    )


def build(db: str, clock: FakeClock, *, skew: int = 0, grace: int = 3600):
    storage = Storage(db)
    keys = KeyStore(storage, clock)
    svc = PresignedService(
        settings=settings_for(db, skew=skew, grace=grace),
        storage=storage, keys=keys, clock=clock, base_url=BASE,
    )
    return TestClient(create_app(svc)), storage, keys, svc


def show(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        db = f"{d}/demo.db"
        clock = FakeClock(T0)
        client, storage, keys, svc = build(db, clock)

        show("1. issue a single-use presigned URL")
        r = client.post(
            "/grants",
            headers={"Authorization": "Bearer token-a"},
            json={"resource_path": "/data/a/report.pdf", "operation": "read",
                  "ttl_seconds": 300, "max_uses": 1},
        )
        grant = r.json()
        path = grant["url"].replace(BASE, "")
        print("url:", grant["url"])

        show("2. first consume succeeds, replay is rejected deterministically")
        print("first :", client.get(path).json())
        again = client.get(path)
        print("replay:", again.status_code, again.json())

        show("3. expiry rejects replays of otherwise valid URLs")
        r = client.post(
            "/grants",
            headers={"Authorization": "Bearer token-a"},
            json={"resource_path": "/data/a/expiring", "operation": "read",
                  "ttl_seconds": 60, "max_uses": 5},
        )
        epath = r.json()["url"].replace(BASE, "")
        clock.set(T0 + 61)
        print("expired:", client.get(epath).status_code, client.get(epath).json())
        clock.set(T0)

        show("4. clock skew tolerance (rebuild with skew=30)")
        client, storage, keys, _ = build(db, clock, skew=30)
        r = client.post(
            "/grants",
            headers={"Authorization": "Bearer token-a"},
            json={"resource_path": "/data/a/skewed", "operation": "read",
                  "ttl_seconds": 60, "max_uses": 5},
        )
        spath = r.json()["url"].replace(BASE, "")
        clock.set(T0 + 85)
        print("at exp+25 (<= skew 30):", client.get(spath).status_code)
        clock.set(T0 + 91)
        print("at exp+31 (> skew 30) :", client.get(spath).status_code)
        clock.set(T0)

        show("5. out-of-scope issuance is rejected and audited")
        denied = client.post(
            "/grants",
            headers={"Authorization": "Bearer token-a"},
            json={"resource_path": "/data/b/secret", "operation": "read",
                  "ttl_seconds": 60},
        )
        print("status:", denied.status_code, denied.json())

        show("6. key rotation: old key valid in grace, dead after grace")
        client, storage, keys, _ = build(db, clock, skew=30, grace=3600)
        r = client.post(
            "/grants",
            headers={"Authorization": "Bearer token-a"},
            json={"resource_path": "/data/a/rotated", "operation": "read",
                  "ttl_seconds": 10_000_000, "max_uses": 5},
        )
        kpath = r.json()["url"].replace(BASE, "")
        client.post("/keys/rotate", headers={"Authorization": "Bearer token-admin"})
        clock.advance(3599)
        print("within grace :", client.get(kpath).status_code)
        clock.advance(2)
        print("after grace  :", client.get(kpath).status_code)
        clock.set(T0)

        show("7. restart recovery: used count survives a new process")
        r = client.post(
            "/grants",
            headers={"Authorization": "Bearer token-a"},
            json={"resource_path": "/data/a/persistent", "operation": "read",
                  "ttl_seconds": 3600, "max_uses": 2},
        )
        ppath = r.json()["url"].replace(BASE, "")
        gid = r.json()["grant_id"]
        client.get(ppath)
        client2, _, _, _ = build(db, clock, skew=30, grace=3600)
        print("after restart consume:", client2.get(ppath).json())
        print("after restart cap    :", client2.get(ppath).status_code)

        show("8. revoke + cleanup: revoked != never issued")
        r = client.post(
            "/grants",
            headers={"Authorization": "Bearer token-a"},
            json={"resource_path": "/data/a/revokable", "operation": "read",
                  "ttl_seconds": 3600, "max_uses": 5},
        )
        rid = r.json()["grant_id"]
        rurl = r.json()["url"].replace(BASE, "")
        client.post("/grants/revoke", headers={"Authorization": "Bearer token-a"},
                    json={"grant_ids": [rid]})
        print("revoked consume:", client.get(rurl).status_code)
        client.post("/grants/cleanup", json={"grant_ids": [rid]})
        admin = {"Authorization": "Bearer token-admin"}
        print("tombstone  :", client.get(f"/grants/{rid}", headers=admin).json()["state"])
        print("never seen :", client.get("/grants/deadbeef", headers=admin)
              .json()["state"])

        show("9. audit trail (latest 5)")
        for e in client.get("/audit?limit=5", headers=admin).json()["events"]:
            print(f"  {e['event_time']} {e['event_type']:<10} {e['result']:<7}"
                  f" {e['reason'] or '-'} gid={e['grant_id']}")

        print("\nACCEPTANCE_DEMO_OK")


if __name__ == "__main__":
    main()
