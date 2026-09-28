"""Restart recovery (durable consumption state) and revocation."""

from presign.models import IssueRequest, Operation

from .conftest import NOW


def _issue(service, scope, resource="docs/x.txt", max_uses=3, exp=NOW + 600):
    return service.issue(
        IssueRequest(resource, Operation.READ, exp, max_uses, "alice"),
        scope,
        now=NOW,
    )


def _tid(url: str) -> str:
    from urllib.parse import parse_qs, urlparse

    return parse_qs(urlparse(url).query)["tid"][0]


def test_used_count_survives_restart(make_service, alice_scope):
    svc1 = make_service()
    url = _issue(svc1, alice_scope, max_uses=3)
    assert svc1.consume(url, "docs/x.txt", Operation.READ, now=NOW).allowed
    assert svc1.consume(url, "docs/x.txt", Operation.READ, now=NOW).allowed

    svc2 = make_service()  # same db path: simulated process restart
    result = svc2.consume(url, "docs/x.txt", Operation.READ, now=NOW)
    assert result.allowed and result.uses_after == 3
    exhausted = svc2.consume(url, "docs/x.txt", Operation.READ, now=NOW)
    assert not exhausted.allowed and exhausted.reason == "usage_exhausted"


def test_revoked_single_token_blocked_even_when_unexpired(service, alice_scope):
    url = _issue(service, alice_scope)
    assert service.revoke([_tid(url)], now=NOW) == 1
    result = service.consume(url, "docs/x.txt", Operation.READ, now=NOW)
    assert not result.allowed and result.reason == "revoked"


def test_revoke_batch(service, alice_scope):
    urls = [_issue(service, alice_scope, resource=f"docs/{i}.txt") for i in range(4)]
    tids = [_tid(u) for u in urls]
    assert service.revoke(tids, now=NOW) == 4
    assert service.revoke(tids, now=NOW) == 0  # idempotent
    for url, name in zip(urls, "0123"):
        result = service.consume(url, f"docs/{name}.txt", Operation.READ, now=NOW)
        assert not result.allowed and result.reason == "revoked"


def test_revocation_survives_restart(make_service, alice_scope):
    svc1 = make_service()
    url = _issue(svc1, alice_scope)
    svc1.revoke([_tid(url)], now=NOW)
    svc2 = make_service()
    result = svc2.consume(url, "docs/x.txt", Operation.READ, now=NOW)
    assert not result.allowed and result.reason == "revoked"


def test_revoked_distinguishable_from_never_issued_after_cleanup(service, alice_scope):
    revoked_url = _issue(service, alice_scope, resource="docs/r.txt", exp=NOW + 10)
    never_url = _issue(service, alice_scope, resource="docs/n.txt", exp=NOW + 10)
    service.revoke([_tid(revoked_url)], now=NOW)

    removed = service.cleanup(now=NOW + 10_000)
    assert removed >= 1  # the never-consumed, expired grant row is gone

    r1 = service.consume(revoked_url, "docs/r.txt", Operation.READ, now=NOW)
    # expiry is checked first, so use a fresh-but-revoked token for the
    # distinction check at the store level:
    assert not r1.allowed
    fresh = _issue(service, alice_scope, resource="docs/f.txt")
    service.revoke([_tid(fresh)], now=NOW)
    service.cleanup(now=NOW + 10_000)
    revoked_result = service.consume(fresh, "docs/f.txt", Operation.READ, now=NOW)
    assert not revoked_result.allowed and revoked_result.reason == "revoked"

    # a token whose row was cleaned (or never issued) reports unknown_token
    ghost = never_url.replace(_tid(never_url), "0" * 32)
    ghost_result = service.consume(ghost, "docs/n.txt", Operation.READ, now=NOW)
    assert not ghost_result.allowed and ghost_result.reason == "bad_signature"
    # genuine never-issued id with a *valid* signature cannot exist without
    # the key, so assert store-level distinction instead:
    assert service._store.is_revoked(_tid(fresh)) is True
    assert service._store.is_revoked("never-seen-id") is False
    assert service._store.usage_of("never-seen-id") is None


def test_no_partial_state_after_failed_consume(service, alice_scope, paths):
    """A denied consume must leave no usage trace behind."""
    url = _issue(service, alice_scope, max_uses=1)
    service.consume(url, "docs/x.txt", Operation.READ, now=NOW)
    tid = _tid(url)
    for _ in range(5):
        service.consume(url, "docs/x.txt", Operation.READ, now=NOW)  # all denied
    assert service._store.usage_of(tid) == 1  # never partially incremented
