"""String-level format-preserving cipher on top of FF1 / FF3-1 numeral algorithms."""

from __future__ import annotations

from enum import StrEnum

from privkit.errors import InvalidInputError
from privkit.fpe.alphabet import Alphabet
from privkit.fpe.ff1 import FF1
from privkit.fpe.ff3_1 import FF3_1, FF3_1_TWEAK_LEN


class Algorithm(StrEnum):
    FF1 = "ff1"
    FF3_1 = "ff3-1"


class FormatPreservingCipher:
    """Encrypts strings over an :class:`Alphabet` without changing length or alphabet.

    >>> from privkit.fpe import DIGITS
    >>> c = FormatPreservingCipher(bytes(16), DIGITS)
    >>> token = c.encrypt("0123456789")
    >>> len(token), token.isdigit(), c.decrypt(token)
    (10, True, '0123456789')
    """

    def __init__(self, key: bytes, alphabet: Alphabet, algorithm: Algorithm = Algorithm.FF1) -> None:
        self.alphabet = alphabet
        self.algorithm = Algorithm(algorithm)
        self._impl: FF1 | FF3_1
        if self.algorithm is Algorithm.FF1:
            self._impl = FF1(key, alphabet.radix)
        else:
            self._impl = FF3_1(key, alphabet.radix)

    @property
    def minlen(self) -> int:
        return self._impl.minlen

    @property
    def maxlen(self) -> int:
        return self._impl.maxlen

    def _tweak(self, tweak: bytes | None) -> bytes:
        if self.algorithm is Algorithm.FF1:
            return tweak or b""
        if tweak is None:
            return bytes(FF3_1_TWEAK_LEN)
        if len(tweak) != FF3_1_TWEAK_LEN:
            raise InvalidInputError("FF3-1 tweak must be exactly 7 bytes")
        return tweak

    def encrypt(self, plaintext: str, tweak: bytes | None = None) -> str:
        numerals = self.alphabet.to_numerals(plaintext)
        out = self._impl.encrypt_numerals(numerals, self._tweak(tweak))
        return self.alphabet.from_numerals(out)

    def decrypt(self, ciphertext: str, tweak: bytes | None = None) -> str:
        numerals = self.alphabet.to_numerals(ciphertext)
        out = self._impl.decrypt_numerals(numerals, self._tweak(tweak))
        return self.alphabet.from_numerals(out)
