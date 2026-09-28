import os

import pytest

from presign.audit import AuditLogger
from presign.models import Operation, Scope
from presign.service import PresignService
from presign.signing import KeyStore
from presign.store import StateStore

NOW = 1_700_000_000  # fixed reference time for deterministic tests


@pytest.fixture()
def paths(tmp_path):
    return {
        "db": os.path.join(tmp_path, "state.db"),
        "audit": os.path.join(tmp_path, "audit.log"),
    }


@pytest.fixture()
def make_service(paths):
    """Factory so a test can rebuild the service (simulating a restart)."""
    services = []

    def build(clock_skew=30, rotation_grace=300, scopes=None):
        svc = PresignService(
            keys=KeyStore("k1", {"k1": "secret-one"}),
            store=StateStore(paths["db"]),
            audit=AuditLogger(paths["audit"]),
            clock_skew_seconds=clock_skew,
            rotation_grace_seconds=rotation_grace,
            scopes=scopes
            or {"alice": Scope("alice", "docs/", frozenset({Operation.READ}))},
        )
        services.append(svc)
        return svc

    yield build
    for svc in services:
        svc._store.close()


@pytest.fixture()
def service(make_service):
    return make_service()


@pytest.fixture()
def alice_scope():
    return Scope("alice", "docs/", frozenset({Operation.READ}))
