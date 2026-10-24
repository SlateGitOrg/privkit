"""FF3-1 format-preserving encryption, implemented from NIST SP 800-38G Rev. 1, section 5.2.

FF3-1 is an 8-round Feistel network whose round function is a single AES call
under the byte-reversed key. Rev. 1 shortened the tweak from 64 to 56 bits to
fix the Durak-Vaudenay attack on the original FF3; only FF3-1 is offered here.

The standard's REV (reverse a numeral string) and REVB (reverse a byte string)
operations are applied exactly as written so the implementation can be checked
line by line against Algorithms 9 and 10.
"""

from __future__ import annotations

from collections.abc import Sequence

from privkit.errors import InvalidInputError
from privkit.fpe._numeral import (
    _BlockCipher,
    check_key,
    min_length,
    num_bytes,
    num_radix,
    str_radix,
    validate_numerals,
)
from privkit.fpe.alphabet import MAX_RADIX

FF3_1_TWEAK_LEN = 7  # 56 bits
FF3_1_ROUNDS = 8


def ff3_1_maxlen(radix: int) -> int:
    """maxlen = 2 * floor(log_radix(2^96)), computed with exact integer arithmetic."""
    k, power = 0, radix
    while power <= 1 << 96:
        k += 1
        power *= radix
    return 2 * k


class FF3_1:  # noqa: N801 - name follows the standard
    """FF3-1 over a fixed key and radix; tweaks are exactly 7 bytes."""

    def __init__(self, key: bytes, radix: int) -> None:
        if not 2 <= radix <= MAX_RADIX:
            raise InvalidInputError(f"radix must be in [2, {MAX_RADIX}]")
        check_key(key)
        self._cipher = _BlockCipher(key[::-1])  # CIPH_REVB(K)
        self.radix = radix
        self.minlen = min_length(radix)
        self.maxlen = ff3_1_maxlen(radix)
        if self.minlen > self.maxlen:
            raise InvalidInputError("radix too large for FF3-1")

    @staticmethod
    def _split_tweak(tweak: bytes) -> tuple[bytes, bytes]:
        if len(tweak) != FF3_1_TWEAK_LEN:
            raise InvalidInputError("FF3-1 tweak must be exactly 7 bytes (56 bits)")
        # T_L = T[0..27] || 0^4 ; T_R = T[32..55] || T[28..31] || 0^4
        t_l = tweak[:3] + bytes([tweak[3] & 0xF0])
        t_r = tweak[4:7] + bytes([(tweak[3] & 0x0F) << 4])
        return t_l, t_r

    def _round_value(self, w: bytes, i: int, x_rev_num: int) -> int:
        head = bytes(a ^ c for a, c in zip(w, i.to_bytes(4, "big"), strict=True))
        p = head + x_rev_num.to_bytes(12, "big")
        s = self._cipher.block(p[::-1])[::-1]  # S = REVB(CIPH_REVB(K)(REVB(P)))
        return num_bytes(s)

    def encrypt_numerals(self, numerals: Sequence[int], tweak: bytes) -> list[int]:
        """FF3-1.Encrypt(K, T, X) of SP 800-38G Rev. 1 Algorithm 9."""
        t_l, t_r = self._split_tweak(tweak)
        validate_numerals(numerals, self.radix, self.minlen, self.maxlen)
        n = len(numerals)
        u = (n + 1) // 2
        v = n - u
        radix = self.radix
        a = list(numerals[:u])
        b = list(numerals[u:])
        for i in range(FF3_1_ROUNDS):
            m, w = (u, t_r) if i % 2 == 0 else (v, t_l)
            y = self._round_value(w, i, num_radix(b[::-1], radix))
            c = (num_radix(a[::-1], radix) + y) % (radix**m)
            a, b = b, str_radix(c, radix, m)[::-1]
        return a + b

    def decrypt_numerals(self, numerals: Sequence[int], tweak: bytes) -> list[int]:
        """FF3-1.Decrypt(K, T, Y) of SP 800-38G Rev. 1 Algorithm 10."""
        t_l, t_r = self._split_tweak(tweak)
        validate_numerals(numerals, self.radix, self.minlen, self.maxlen)
        n = len(numerals)
        u = (n + 1) // 2
        v = n - u
        radix = self.radix
        a = list(numerals[:u])
        b = list(numerals[u:])
        for i in range(FF3_1_ROUNDS - 1, -1, -1):
            m, w = (u, t_r) if i % 2 == 0 else (v, t_l)
            y = self._round_value(w, i, num_radix(a[::-1], radix))
            c = (num_radix(b[::-1], radix) - y) % (radix**m)
            b, a = a, str_radix(c, radix, m)[::-1]
        return a + b
