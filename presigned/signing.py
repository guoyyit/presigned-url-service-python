"""Sign/verify the canonical representation of a presigned grant.

Canonical signing string (newline separated, no ambiguity with the values
themselves because integer fields are constrained and ``max_uses`` uses the
literal ``unlimited``)::

    HMAC-SHA256
    <grant_id>
    <resource_path>
    <operation>
    <expires_at>
    <max_uses | "unlimited">
    <issued_at>
    <key_id>

The signature and every constraint parameter travel in the query string of
the consume endpoint, e.g.::

    /consume?kid=k1f2..&gid=...&p=%2Fdata%2Fa%2Ff&op=read
        &exp=1760000000&n=1&iat=1750000000&sig=<hex hmac-sha256>

Tampering with *any* parameter changes the canonical message and therefore
invalidates the signature.
"""

from __future__ import annotations

from urllib.parse import ParseResult, parse_qs, urlencode, urlparse, urlunparse

from presigned.crypto import KeyStore, hmac_verify
from presigned.errors import InvalidRequestError, InvalidSignatureError
from presigned.models import PresignedURL

CONSUME_PATH = "/consume"


def canonical_message(
    *,
    grant_id: str,
    resource_path: str,
    operation: str,
    expires_at: int,
    max_uses: int | None,
    issued_at: int,
    key_id: str,
    alg: str = "HMAC-SHA256",
) -> bytes:
    n = "unlimited" if max_uses is None else str(int(max_uses))
    lines = [
        alg,
        grant_id,
        resource_path,
        operation,
        str(int(expires_at)),
        n,
        str(int(issued_at)),
        key_id,
    ]
    return "\n".join(lines).encode("utf-8")


def build_url(base: str, path: str, query: dict[str, str]) -> str:
    base_p = urlparse(base)
    scheme = base_p.scheme or "http"
    netloc = base_p.netloc
    return urlunparse((scheme, netloc, path, "", urlencode(query), ""))


def sign_grant(
    *,
    base_url: str,
    grant_id: str,
    resource_path: str,
    operation: str,
    expires_at: int,
    max_uses: int | None,
    issued_at: int,
    keys: KeyStore,
    alg: str = "HMAC-SHA256",
) -> PresignedURL:
    key = keys.current()
    msg = canonical_message(
        grant_id=grant_id,
        resource_path=resource_path,
        operation=operation,
        expires_at=expires_at,
        max_uses=max_uses,
        issued_at=issued_at,
        key_id=key.key_id,
        alg=alg,
    )
    from presigned.crypto import hmac_sign

    signature = hmac_sign(key.secret, msg)
    query = {
        "kid": key.key_id,
        "gid": grant_id,
        "p": resource_path,
        "op": operation,
        "exp": str(int(expires_at)),
        "n": "unlimited" if max_uses is None else str(int(max_uses)),
        "iat": str(int(issued_at)),
        "alg": alg,
        "sig": signature,
    }
    url = build_url(base_url, CONSUME_PATH, query)
    return PresignedURL(
        url=url,
        grant_id=grant_id,
        resource_path=resource_path,
        operation=operation,
        expires_at=int(expires_at),
        max_uses=max_uses,
        issued_at=int(issued_at),
        key_id=key.key_id,
        signature=signature,
    )


def _one(qs: dict[str, list[str]], name: str) -> str:
    values = qs.get(name)
    if not values or len(values) != 1 or values[0] == "":
        raise InvalidRequestError(f"missing or duplicated query parameter: {name}")
    return values[0]


def parse_signed_url(url: ParseResult | str) -> PresignedURL:
    """Parse a presigned URL without verifying it."""
    parsed = urlparse(url) if isinstance(url, str) else url
    url_text = url if isinstance(url, str) else urlunparse(parsed)
    qs = parse_qs(parsed.query, keep_blank_values=False)
    try:
        kid = _one(qs, "kid")
        gid = _one(qs, "gid")
        resource_path = _one(qs, "p")
        operation = _one(qs, "op")
        exp = int(_one(qs, "exp"))
        n_raw = _one(qs, "n")
        iat = int(_one(qs, "iat"))
        alg = _one(qs, "alg")
        sig = _one(qs, "sig")
    except InvalidRequestError:
        raise
    except (KeyError, ValueError) as exc:
        raise InvalidRequestError(f"malformed presigned url: {exc}") from exc
    max_uses: int | None
    if n_raw == "unlimited":
        max_uses = None
    else:
        try:
            max_uses = int(n_raw)
        except ValueError as exc:
            raise InvalidRequestError("malformed max uses parameter") from exc
        if max_uses < 1:
            raise InvalidRequestError("max uses must be >= 1")
    raw = parsed if isinstance(url, str) is False else None
    if exp <= iat:
        raise InvalidRequestError("expires_at must be after issued_at")
    return PresignedURL(
        url=url_text,
        grant_id=gid,
        resource_path=resource_path,
        operation=operation,
        expires_at=exp,
        max_uses=max_uses,
        issued_at=iat,
        key_id=kid,
        signature=sig,
    )


def verify_url(
    url: PresignedURL | ParseResult | str,
    keys: KeyStore,
    *,
    alg: str = "HMAC-SHA256",
) -> PresignedURL:
    """Verify signature structurally. Expiry/usage are enforced elsewhere."""
    parsed = parse_signed_url(url) if not isinstance(url, PresignedURL) else url
    key = keys.get(parsed.key_id)
    if key is None:
        raise InvalidSignatureError("unknown signing key", grant_id=parsed.grant_id)
    msg = canonical_message(
        grant_id=parsed.grant_id,
        resource_path=parsed.resource_path,
        operation=parsed.operation,
        expires_at=parsed.expires_at,
        max_uses=parsed.max_uses,
        issued_at=parsed.issued_at,
        key_id=parsed.key_id,
        alg=alg,
    )
    if not hmac_verify(key.secret, msg, parsed.signature):
        raise InvalidSignatureError("signature mismatch", grant_id=parsed.grant_id)
    return parsed
