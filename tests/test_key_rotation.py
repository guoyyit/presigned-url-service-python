"""Key rotation: old-key tokens verify during the grace window, must
fail after it, and rotation racing verification is consistent."""

import threading

from presign.models import IssueRequest, Operation

from .conftest import NOW


def _issue(service, scope, now=NOW):
    return service.issue(
        IssueRequest("docs/r.txt", Operation.READ, now + 3600, None, "alice"),
        scope,
        now=now,
    )


def test_old_key_valid_within_grace(service, alice_scope):
    url = _issue(service, alice_scope)
    service.rotate_key("k2", "secret-two", now=NOW + 100)
    result = service.consume(url, "docs/r.txt", Operation.READ, now=NOW + 100 + 299)
    assert result.allowed


def test_old_key_fails_after_grace(service, alice_scope):
    url = _issue(service, alice_scope)
    service.rotate_key("k2", "secret-two", now=NOW + 100)
    result = service.consume(url, "docs/r.txt", Operation.READ, now=NOW + 100 + 301)
    assert not result.allowed and result.reason == "key_retired"


def test_new_key_signs_after_rotation(service, alice_scope):
    service.rotate_key("k2", "secret-two", now=NOW)
    url = _issue(service, alice_scope, now=NOW + 1)
    assert "kid=k2" in url
    assert service.consume(url, "docs/r.txt", Operation.READ, now=NOW + 2).allowed


def test_unknown_key_rejected(service, alice_scope):
    url = _issue(service, alice_scope).replace("kid=k1", "kid=k9")
    result = service.consume(url, "docs/r.txt", Operation.READ, now=NOW)
    assert not result.allowed and result.reason == "bad_signature"


def test_double_rotation_retires_intermediate_key(service, alice_scope):
    url_k1 = _issue(service, alice_scope)
    service.rotate_key("k2", "secret-two", now=NOW + 100)
    url_k2 = _issue(service, alice_scope, now=NOW + 101)
    service.rotate_key("k3", "secret-three", now=NOW + 200)

    # k1 and k2 both inside their own grace windows
    r1 = service.consume(url_k1, "docs/r.txt", Operation.READ, now=NOW + 100 + 299)
    r2 = service.consume(url_k2, "docs/r.txt", Operation.READ, now=NOW + 200 + 299)
    assert r1.allowed and r2.allowed
    # k2's grace ends at NOW+500; k1's at NOW+400
    late1 = service.consume(url_k1, "docs/r.txt", Operation.READ, now=NOW + 401)
    late2 = service.consume(url_k2, "docs/r.txt", Operation.READ, now=NOW + 501)
    assert not late1.allowed and late1.reason == "key_retired"
    assert not late2.allowed and late2.reason == "key_retired"


def test_rotation_racing_verification_is_consistent(service, alice_scope):
    """A consume racing a rotation must always succeed (old key is either
    still active or retired-but-in-grace); never a spurious failure."""
    url = _issue(service, alice_scope)
    outcomes = []
    barrier = threading.Barrier(2)

    def rotator():
        barrier.wait()
        service.rotate_key("k2", "secret-two", now=NOW)

    def consumer():
        barrier.wait()
        for _ in range(200):
            outcomes.append(
                service.consume(url, "docs/r.txt", Operation.READ, now=NOW).allowed
            )

    t1, t2 = threading.Thread(target=rotator), threading.Thread(target=consumer)
    t1.start(); t2.start(); t1.join(); t2.join()
    assert all(outcomes), "consume must succeed before, during and after rotation"


def test_rotation_is_audited(service, alice_scope, paths):
    import json

    service.rotate_key("k2", "secret-two", now=NOW)
    with open(paths["audit"]) as fh:
        events = [json.loads(line) for line in fh]
    rotated = [e for e in events if e["event"] == "key_rotated"]
    assert rotated and rotated[0]["retired_key_id"] == "k1"
    assert rotated[0]["active_key_id"] == "k2"


def test_issue_racing_rotation_always_produces_valid_tokens(service, alice_scope):
    """A token issued while a rotation happens must still verify: the key
    id embedded in the signed payload always matches the signing key."""
    import threading

    issued = []
    barrier = threading.Barrier(2)
    stop = threading.Event()

    def rotator():
        barrier.wait()
        for i in range(50):
            service.rotate_key(f"kr{i}", f"secret-{i}", now=NOW)
        stop.set()

    def issuer():
        barrier.wait()
        while not stop.is_set():
            issued.append(_issue(service, alice_scope))

    t1, t2 = threading.Thread(target=rotator), threading.Thread(target=issuer)
    t1.start(); t2.start(); t1.join(); t2.join()

    assert issued, "issuer should have produced tokens during rotations"
    for url in issued:
        result = service.consume(url, "docs/r.txt", Operation.READ, now=NOW)
        assert result.allowed, f"token issued during rotation must verify: {url}"
