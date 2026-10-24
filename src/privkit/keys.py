"""Key loading and derivation.

privkit takes one *master key* (256-bit recommended) and derives an independent
AES key per purpose with HKDF-SHA256 (RFC 5869). Distinct per-field keys mean a
token produced for one column cannot be correlated with, or decrypted as, a
token for another column.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from privkit.errors import KeyMaterialError

DEFAULT_KEY_ENV = "PRIVKIT_KEY"
_HKDF_SALT = b"privkit/v1/hkdf-salt"
_VALID_LENGTHS = (16, 24, 32)


def parse_key(text: str) -> bytes:
    """Parse a 128/192/256-bit key given as hex or (url-safe) base64."""
    raw = text.strip()
    candidates: list[bytes] = []
    with contextlib.suppress(ValueError):
        candidates.append(bytes.fromhex(raw))
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            candidates.append(decoder(raw + "=" * (-len(raw) % 4)))
        except (binascii.Error, ValueError):
            continue
    for key in candidates:
        if len(key) in _VALID_LENGTHS:
            return key
    raise KeyMaterialError("key must be 16, 24 or 32 bytes encoded as hex or base64")


def key_from_env(var: str = DEFAULT_KEY_ENV) -> bytes:
    """Read and parse the master key from environment variable ``var``."""
    value = os.environ.get(var)
    if not value:
        raise KeyMaterialError(f"environment variable {var} is not set")
    return parse_key(value)


def derive_key(master: bytes, purpose: str, length: int = 32) -> bytes:
    """HKDF-SHA256(master, salt, info=purpose) -> ``length`` bytes."""
    if len(master) not in _VALID_LENGTHS:
        raise KeyMaterialError("master key must be 16, 24 or 32 bytes")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=_HKDF_SALT, info=purpose.encode())
    return hkdf.derive(master)


def generate_key_hex(nbytes: int = 32) -> str:
    """A fresh random master key, hex encoded, from the OS CSPRNG."""
    if nbytes not in _VALID_LENGTHS:
        raise KeyMaterialError("key length must be 16, 24 or 32 bytes")
    return secrets.token_hex(nbytes)
