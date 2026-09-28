"""Signing key management: issue, rotation, and verification.

Tokens are authenticated with HMAC-SHA256. The key store supports
rotation: a newly rotated-in key signs new tokens while the retired key
remains usable for verification until its grace deadline passes.

Concurrency: a single lock guards all key state, so a rotation that
races with verification yields a consistent result -- a verify either
sees the pre-rotation key set (and succeeds) or the post-rotation set
(where the retired key still verifies until its grace deadline).
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Callable


def _mac(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


class KeyStore:
    """Holds the active signing key and retired keys with grace deadlines."""

    def __init__(self, active_key_id: str, keys: dict[str, str]) -> None:
        if active_key_id not in keys:
            raise ValueError(f"active key id {active_key_id!r} has no secret")
        self._lock = threading.Lock()
        self._active_key_id = active_key_id
        self._keys = dict(keys)
        # key id -> unix time after which the key may no longer verify
        self._retired_until: dict[str, int] = {}

    @property
    def active_key_id(self) -> str:
        with self._lock:
            return self._active_key_id

    def rotate(self, new_key_id: str, new_secret: str, now: int, grace: int) -> str:
        """Rotate in a new active key; retire the old one with a grace period.

        Returns the id of the retired key.
        """
        with self._lock:
            retired = self._active_key_id
            self._keys[new_key_id] = new_secret
            self._active_key_id = new_key_id
            # The retired key keeps verifying until now + grace; any prior
            # grace deadline for a re-rotated key is superseded.
            self._retired_until[retired] = now + grace
            self._retired_until.pop(new_key_id, None)
            return retired

    def sign(self, payload_for: Callable[[str], bytes]) -> tuple[str, str]:
        """Sign with the active key, atomically.

        ``payload_for`` receives the actual key id and returns the payload
        to sign, so the key id embedded in the payload always matches the
        key that signs it -- even if a rotation happens concurrently.
        Returns (key_id, hex mac).
        """
        with self._lock:
            key_id = self._active_key_id
            mac = _mac(self._keys[key_id], payload_for(key_id))
        return key_id, mac

    def verify(self, key_id: str, payload: bytes, mac_hex: str, now: int) -> bool:
        """Verify ``mac_hex`` against the named key, honoring grace deadlines."""
        with self._lock:
            if self._key_status_locked(key_id, now) not in ("active", "retired_valid"):
                return False
            secret = self._keys[key_id]
        return hmac.compare_digest(_mac(secret, payload), mac_hex)

    def _key_status_locked(self, key_id: str, now: int) -> str:
        if key_id not in self._keys:
            return "unknown"
        if key_id == self._active_key_id:
            return "active"
        deadline = self._retired_until.get(key_id)
        if deadline is None or now > deadline:
            return "retired_expired"
        return "retired_valid"

    def key_status(self, key_id: str, now: int) -> str:
        """One of: "active", "retired_valid", "retired_expired", "unknown"."""
        with self._lock:
            return self._key_status_locked(key_id, now)
