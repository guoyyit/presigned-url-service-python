"""Issuance scope: resource prefix, operation type and caller identity.
Violations are denied and leave an audit trail."""

import json

import pytest

from presign.errors import IssueDenied
from presign.models import IssueRequest, Operation, Scope

from .conftest import NOW


def _req(resource="docs/a.txt", op=Operation.READ, issuer="alice"):
    return IssueRequest(resource, op, NOW + 600, None, issuer)


def test_issue_within_scope(service, alice_scope):
    url = service.issue(_req(), alice_scope, now=NOW)
    assert url.startswith("/presign/access?")


def test_resource_outside_prefix_denied(service, alice_scope):
    with pytest.raises(IssueDenied) as exc:
        service.issue(_req(resource="private/secret.txt"), alice_scope, now=NOW)
    assert exc.value.reason == "out_of_scope"


def test_prefix_boundary_is_strict(service, alice_scope):
    # "docs" without slash must not match prefix "docs/"
    with pytest.raises(IssueDenied):
        service.issue(_req(resource="docs"), alice_scope, now=NOW)
    # but nested paths under the prefix are fine
    url = service.issue(_req(resource="docs/a/b/c.txt"), alice_scope, now=NOW)
    assert url


def test_operation_outside_scope_denied(service):
    # only READ exists today; simulate a scope that lacks the requested op
    # by requesting an op not in the scope set
    with pytest.raises(IssueDenied) as exc:
        service._check_scope(_req(op=Operation.READ), Scope("alice", "docs/", frozenset()))
    assert exc.value.reason == "out_of_scope"


def test_identity_mismatch_denied(service, alice_scope):
    with pytest.raises(IssueDenied) as exc:
        service.issue(_req(issuer="mallory"), alice_scope, now=NOW)
    assert exc.value.reason == "out_of_scope"


def test_access_with_wrong_resource_denied(service, alice_scope):
    url = service.issue(_req(resource="docs/a.txt"), alice_scope, now=NOW)
    result = service.consume(url, "docs/b.txt", Operation.READ, now=NOW)
    assert not result.allowed and result.reason == "resource_mismatch"


def test_scope_violations_are_audited(service, alice_scope, paths):
    for bad in (
        _req(resource="etc/passwd"),
        _req(issuer="mallory"),
    ):
        with pytest.raises(IssueDenied):
            service.issue(bad, alice_scope, now=NOW)
    with open(paths["audit"]) as fh:
        events = [json.loads(line) for line in fh]
    denied = [e for e in events if e["event"] == "issue_denied"]
    assert len(denied) == 2
    assert all(e["reason"] == "out_of_scope" for e in denied)
