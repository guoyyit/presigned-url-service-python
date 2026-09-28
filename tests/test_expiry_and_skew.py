"""Expiry, clock-skew tolerance, and replay/tamper rejection."""

from presign.models import IssueRequest, Operation

from .conftest import NOW


def _issue(service, scope, **overrides):
    req = IssueRequest(
        resource=overrides.get("resource", "docs/a.txt"),
        operation=Operation.READ,
        expires_at=overrides.get("expires_at", NOW + 600),
        max_uses=overrides.get("max_uses"),
        issuer="alice",
    )
    return service.issue(req, scope, now=overrides.get("now", NOW))


def test_valid_token_consumes(service, alice_scope):
    url = _issue(service, alice_scope)
    result = service.consume(url, "docs/a.txt", Operation.READ, now=NOW)
    assert result.allowed and result.reason == "ok"


def test_expired_token_rejected(service, alice_scope):
    url = _issue(service, alice_scope, expires_at=NOW + 100)
    result = service.consume(url, "docs/a.txt", Operation.READ, now=NOW + 100 + 31)
    assert not result.allowed and result.reason == "expired"


def test_clock_skew_tolerated_within_bound(service, alice_scope):
    url = _issue(service, alice_scope, expires_at=NOW + 100)
    # consumer clock is 30s ahead of expiry: within the default skew
    result = service.consume(url, "docs/a.txt", Operation.READ, now=NOW + 100 + 30)
    assert result.allowed


def test_clock_skew_configurable(make_service, alice_scope):
    strict = make_service(clock_skew=0)
    url = _issue(strict, alice_scope, expires_at=NOW + 100)
    result = strict.consume(url, "docs/a.txt", Operation.READ, now=NOW + 101)
    assert not result.allowed and result.reason == "expired"

    lenient = make_service(clock_skew=120)
    url2 = _issue(lenient, alice_scope, expires_at=NOW + 100)
    result = lenient.consume(url2, "docs/a.txt", Operation.READ, now=NOW + 100 + 119)
    assert result.allowed


def test_future_dated_token_rejected(service, alice_scope):
    # issued "in the future" beyond skew -> not yet valid
    url = _issue(service, alice_scope, now=NOW + 10_000, expires_at=NOW + 20_000)
    result = service.consume(url, "docs/a.txt", Operation.READ, now=NOW)
    assert not result.allowed and result.reason == "not_yet_valid"


def test_expired_replay_still_rejected(service, alice_scope):
    url = _issue(service, alice_scope, expires_at=NOW + 10, max_uses=5)
    assert service.consume(url, "docs/a.txt", Operation.READ, now=NOW).allowed
    for attempt in range(3):
        result = service.consume(url, "docs/a.txt", Operation.READ, now=NOW + 10_000)
        assert not result.allowed and result.reason == "expired"


def test_tampering_any_parameter_fails(service, alice_scope):
    url = _issue(service, alice_scope, expires_at=NOW + 600, max_uses=3)
    tampered_variants = [
        url.replace("docs%2Fa.txt", "docs%2Fb.txt"),          # resource
        url.replace("op=read", "op=write"),                   # operation
        url.replace(f"exp={NOW + 600}", f"exp={NOW + 9999}"), # expiry
        url.replace("mu=3", "mu=99"),                         # max uses
        url.replace("iss=alice", "iss=mallory"),              # issuer
        url[:-1] + ("0" if url[-1] != "0" else "1"),          # signature
    ]
    for bad in tampered_variants:
        assert bad != url
        result = service.consume(bad, "docs/a.txt", Operation.READ, now=NOW)
        assert not result.allowed, bad
        assert result.reason in ("bad_signature", "malformed")


def test_malformed_token_rejected(service):
    for bad in ("", "not-a-token", "tid=1&r=2", "/presign/access?tid=x"):
        result = service.consume(bad, "docs/a.txt", Operation.READ, now=NOW)
        assert not result.allowed and result.reason == "malformed"
