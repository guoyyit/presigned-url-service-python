"""Limited-use semantics under concurrency: the cumulative use count
must never exceed the authorized maximum, and repeat consumption must
produce deterministic, auditable results."""

import json
import threading

from presign.models import IssueRequest, Operation

from .conftest import NOW


def _issue(service, scope, max_uses):
    return service.issue(
        IssueRequest("docs/hot.bin", Operation.READ, NOW + 600, max_uses, "alice"),
        scope,
        now=NOW,
    )


def test_single_use_allows_exactly_one(service, alice_scope):
    url = _issue(service, alice_scope, max_uses=1)
    assert service.consume(url, "docs/hot.bin", Operation.READ, now=NOW).allowed
    second = service.consume(url, "docs/hot.bin", Operation.READ, now=NOW)
    assert not second.allowed and second.reason == "usage_exhausted"


def test_concurrent_consumption_never_exceeds_max(service, alice_scope):
    max_uses = 5
    url = _issue(service, alice_scope, max_uses)
    results = []
    barrier = threading.Barrier(50)

    def worker():
        barrier.wait()  # maximize contention
        results.append(service.consume(url, "docs/hot.bin", Operation.READ, now=NOW))

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed = [r for r in results if r.allowed]
    denied = [r for r in results if not r.allowed]
    assert len(allowed) == max_uses
    assert all(r.reason == "usage_exhausted" for r in denied)
    # deterministic: uses_after values are exactly 1..max_uses, no duplicates
    assert sorted(r.uses_after for r in allowed) == list(range(1, max_uses + 1))


def test_unlimited_use_allows_all(service, alice_scope):
    url = _issue(service, alice_scope, max_uses=None)
    for _ in range(100):
        assert service.consume(url, "docs/hot.bin", Operation.READ, now=NOW).allowed


def test_denied_consumption_does_not_burn_uses(service, alice_scope):
    url = _issue(service, alice_scope, max_uses=1)
    # wrong resource: denied, must not consume the single use
    bad = service.consume(url, "docs/other.bin", Operation.READ, now=NOW)
    assert not bad.allowed and bad.reason == "resource_mismatch"
    good = service.consume(url, "docs/hot.bin", Operation.READ, now=NOW)
    assert good.allowed


def test_repeat_consumption_is_audited(service, alice_scope, paths):
    url = _issue(service, alice_scope, max_uses=1)
    service.consume(url, "docs/hot.bin", Operation.READ, now=NOW)
    service.consume(url, "docs/hot.bin", Operation.READ, now=NOW)

    with open(paths["audit"]) as fh:
        events = [json.loads(line) for line in fh]
    outcomes = [e for e in events if e["event"].startswith("consume_")]
    assert [e["event"] for e in outcomes] == ["consume_allowed", "consume_denied"]
    assert outcomes[1]["reason"] == "usage_exhausted"
    assert outcomes[0]["token_id"] == outcomes[1]["token_id"]
