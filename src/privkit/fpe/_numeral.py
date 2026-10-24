"""Numeral-string arithmetic shared by FF1 and FF3-1 (SP 800-38G section 4.5)."""

from __future__ import annotations

from collections.abc import Sequence

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from privkit.errors import InvalidInputError, KeyMaterialError

MIN_DOMAIN = 1_000_000  # SP 800-38G Rev. 1: radix^minlen >= 1,000,000


def num_radix(numerals: Sequence[int], radix: int) -> int:
    """NUM_radix(X): the integer whose base-``radix`` digits are ``numerals`` (MSB first)."""
    value = 0
    for digit in numerals:
        value = value * radix + digit
    return value


def str_radix(value: int, radix: int, length: int) -> list[int]:
    """STR^m_radix(x): ``length`` base-``radix`` digits of ``value`` (MSB first)."""
    out = [0] * length
    for i in range(length - 1, -1, -1):
        value, out[i] = divmod(value, radix)
    if value:
        raise InvalidInputError("value does not fit in the requested numeral length")
    return out


def num_bytes(data: bytes) -> int:
    """NUM(X) for a byte string: big-endian unsigned integer."""
    return int.from_bytes(data, "big")


def validate_numerals(numerals: Sequence[int], radix: int, minlen: int, maxlen: int) -> None:
    n = len(numerals)
    if n < minlen or n > maxlen:
        raise InvalidInputError(f"numeral string length {n} outside [{minlen}, {maxlen}]")
    for d in numerals:
        if not 0 <= d < radix:
            raise InvalidInputError("numeral outside [0, radix)")


def min_length(radix: int) -> int:
    """Smallest length with radix^minlen >= 1,000,000 (and at least 2)."""
    length, size = 1, radix
    while size < MIN_DOMAIN:
        length += 1
        size *= radix
    return max(length, 2)


def check_key(key: bytes) -> None:
    if len(key) not in (16, 24, 32):
        raise KeyMaterialError("AES key must be 16, 24 or 32 bytes")


class _BlockCipher:
    """A reusable AES single-block encryption primitive (CIPH_K in the standard)."""

    __slots__ = ("_enc", "_key")

    def __init__(self, key: bytes) -> None:
        check_key(key)
        self._key = key
        # ECB over exactly one block is the raw block cipher; the context is
        # stateless between 16-byte updates so it can be reused.
        self._enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - raw single-block AES

    def block(self, data: bytes) -> bytes:
        return self._enc.update(data)

    def cbc_mac(self, data: bytes) -> bytes:
        """PRF(X) of SP 800-38G: CBC-MAC with a zero IV, returns the last block."""
        enc = Cipher(algorithms.AES(self._key), modes.CBC(bytes(16))).encryptor()
        return enc.update(data)[-16:]
