"""FF1 format-preserving encryption, implemented from NIST SP 800-38G (Rev. 1), section 5.1.

FF1 is a 10-round Feistel network whose round function is an AES-based PRF
(CBC-MAC) followed by AES in counter-like expansion when more than 16 bytes are
needed. Inputs are numeral strings over ``radix``; tweaks are byte strings.

Complexity per call: 10 rounds, each costing O(ceil((t + b) / 16)) AES block
operations plus O(n^2 / w) big-integer arithmetic for NUM/STR conversion
(n = numeral-string length, w = machine word); for realistic n (< 100) the AES
calls dominate.
"""

from __future__ import annotations

from collections.abc import Sequence

from privkit.errors import InvalidInputError
from privkit.fpe._numeral import (
    _BlockCipher,
    min_length,
    num_bytes,
    num_radix,
    str_radix,
    validate_numerals,
)
from privkit.fpe.alphabet import MAX_RADIX

FF1_MAXLEN = 1 << 32
FF1_ROUNDS = 10


class FF1:
    """FF1 over a fixed key and radix.

    ``max_tweak_len`` (bytes) is the implementation-chosen maxTlen of the standard.
    """

    def __init__(self, key: bytes, radix: int, *, max_tweak_len: int = 256) -> None:
        if not 2 <= radix <= MAX_RADIX:
            raise InvalidInputError(f"radix must be in [2, {MAX_RADIX}]")
        if max_tweak_len < 0:
            raise InvalidInputError("max_tweak_len must be non-negative")
        self._cipher = _BlockCipher(key)
        self.radix = radix
        self.minlen = min_length(radix)
        self.maxlen = FF1_MAXLEN
        self.max_tweak_len = max_tweak_len

    def _check(self, numerals: Sequence[int], tweak: bytes) -> None:
        validate_numerals(numerals, self.radix, self.minlen, self.maxlen)
        if len(tweak) > self.max_tweak_len:
            raise InvalidInputError(f"tweak longer than {self.max_tweak_len} bytes")

    def _params(self, n: int, t: int) -> tuple[int, int, int, int, bytes]:
        u = n // 2
        v = n - u
        # b = ceil(ceil(v * log2(radix)) / 8). (radix^v - 1).bit_length() equals
        # ceil(v * log2(radix)) exactly, avoiding floating-point error.
        b = ((self.radix**v - 1).bit_length() + 7) // 8
        d = 4 * ((b + 3) // 4) + 4
        p = (
            bytes([1, 2, 1])
            + self.radix.to_bytes(3, "big")
            + bytes([10, u % 256])
            + n.to_bytes(4, "big")
            + t.to_bytes(4, "big")
        )
        return u, v, b, d, p

    def _round_value(self, p: bytes, tweak: bytes, i: int, x: int, b: int, d: int) -> int:
        t = len(tweak)
        q = tweak + bytes((-t - b - 1) % 16) + bytes([i]) + x.to_bytes(b, "big")
        r = self._cipher.cbc_mac(p + q)
        s = bytearray(r)
        j = 1
        while len(s) < d:
            block = bytes(a ^ c for a, c in zip(r, j.to_bytes(16, "big"), strict=True))
            s += self._cipher.block(block)
            j += 1
        return num_bytes(bytes(s[:d]))

    def encrypt_numerals(self, numerals: Sequence[int], tweak: bytes = b"") -> list[int]:
        """FF1.Encrypt(K, T, X) of SP 800-38G Algorithm 7."""
        self._check(numerals, tweak)
        n = len(numerals)
        u, v, b, d, p = self._params(n, len(tweak))
        radix = self.radix
        a_num = num_radix(numerals[:u], radix)
        b_num = num_radix(numerals[u:], radix)
        mod_u, mod_v = radix**u, radix**v
        for i in range(FF1_ROUNDS):
            y = self._round_value(p, tweak, i, b_num, b, d)
            m_mod = mod_u if i % 2 == 0 else mod_v
            c = (a_num + y) % m_mod
            a_num, b_num = b_num, c
        return str_radix(a_num, radix, u) + str_radix(b_num, radix, v)

    def decrypt_numerals(self, numerals: Sequence[int], tweak: bytes = b"") -> list[int]:
        """FF1.Decrypt(K, T, Y) of SP 800-38G Algorithm 8."""
        self._check(numerals, tweak)
        n = len(numerals)
        u, v, b, d, p = self._params(n, len(tweak))
        radix = self.radix
        a_num = num_radix(numerals[:u], radix)
        b_num = num_radix(numerals[u:], radix)
        mod_u, mod_v = radix**u, radix**v
        for i in range(FF1_ROUNDS - 1, -1, -1):
            y = self._round_value(p, tweak, i, a_num, b, d)
            m_mod = mod_u if i % 2 == 0 else mod_v
            c = (b_num - y) % m_mod
            b_num, a_num = a_num, c
        return str_radix(a_num, radix, u) + str_radix(b_num, radix, v)
