"""Signing primitives and signing-key version store.

Keys never appear in URLs; only a short ``key_id`` travels with the grant so
verification can select the matching secret. The current key signs new
grants; rotated keys remain verifiable during a configurable grace period.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from typing import TYPE_CHECKING

from presigned.clock import Clock
from presigned.models import SigningKey

if TYPE_CHECKING:
    from presigned.storage import Storage


def generate_secret() -> bytes:
    """Return a fresh 256-bit random signing secret."""
    return secrets.token_bytes(32)


def new_key_id() -> str:
    return "k" + secrets.token_hex(6)


def hmac_sign(secret: bytes, message: bytes) -> str:
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def hmac_verify(secret: bytes, message: bytes, signature: str) -> bool:
    expected = hmac_sign(secret, message)
    return hmac.compare_digest(expected, signature)


class KeyStore:
    """Versioned key store.

    Persistence lives in :class:`Storage`; this class adds the "current key"
    notion, rotation and grace-period selection. Rotation is serialized so
    concurrent rotations can never fork the key chain, and verification
    always reads a consistent snapshot.
    """

    def __init__(self, storage: "Storage", clock: Clock) -> None:
        self._storage = storage
        self._clock = clock
        self._lock = threading.Lock()
        keys = storage.load_keys()
        keys.sort(key=lambda k: k.created_at)
        self._keys: dict[str, SigningKey] = {k.key_id: k for k in keys}
        self._current_id: str | None = next(
            (k.key_id for k in reversed(keys) if k.rotated_at is None),
            None,
        )
        if self._current_id is None:
            key = SigningKey(
                key_id=new_key_id(),
                secret=generate_secret(),
                created_at=clock.now(),
            )
            storage.insert_key(key)
            self._keys[key.key_id] = key
            self._current_id = key.key_id

    @property
    def current_key_id(self) -> str:
        return self._current_id  # type: ignore[return-value]

    def current_secret(self) -> bytes:
        return self._keys[self._current_id].secret  # type: ignore[index]

    def current(self) -> SigningKey:
        return self._keys[self._current_id]  # type: ignore[index]

    def get(self, key_id: str) -> SigningKey | None:
        return self._keys.get(key_id)

    def rotate(self, secret: bytes | None = None) -> SigningKey:
        """Install a new current key; the old one enters its grace window."""
        with self._lock:
            now = self._clock.now()
            old_id = self._current_id
            new = SigningKey(
                key_id=new_key_id(),
                secret=secret if secret is not None else generate_secret(),
                created_at=now,
            )
            # Persist both changes before they become visible in memory, so a
            # crash never leaves an unpersisted "current" key.
            self._storage.insert_key(new)
            if old_id is not None:
                self._storage.mark_key_rotated(old_id, now)
            self._keys[new.key_id] = new
            if old_id is not None:
                old = self._keys[old_id]
                self._keys[old_id] = SigningKey(
                    key_id=old.key_id,
                    secret=old.secret,
                    created_at=old.created_at,
                    rotated_at=now,
                )
            self._current_id = new.key_id
            return new

    def verifiable_keys(self, *, grace_period_seconds: int, now: int) -> list[SigningKey]:
        """Current key plus rotated keys still inside their grace window."""
        out: list[SigningKey] = []
        for key in self._keys.values():
            if key.rotated_at is None:
                out.append(key)
            elif grace_period_seconds > 0 and now - key.rotated_at <= grace_period_seconds:
                out.append(key)
        return out
