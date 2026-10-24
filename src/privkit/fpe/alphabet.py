"""Alphabets map characters to numerals for format-preserving encryption.

SP 800-38G works on *numeral strings*: sequences of integers in ``[0, radix)``.
An :class:`Alphabet` is the bijection between those numerals and printable
characters. The order of characters matters: ``"0123456789"`` maps ``"7"`` to the
numeral 7, which is what the NIST sample vectors assume.
"""

from __future__ import annotations

import string
from collections.abc import Sequence
from dataclasses import dataclass, field

from privkit.errors import InvalidInputError

MAX_RADIX = 1 << 16  # SP 800-38G: radix in [2, 2^16]


@dataclass(frozen=True)
class Alphabet:
    """An ordered set of unique characters; its length is the radix."""

    chars: str
    _index: dict[str, int] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if len(self.chars) < 2:
            raise InvalidInputError("an alphabet needs at least two characters")
        if len(self.chars) > MAX_RADIX:
            raise InvalidInputError(f"radix {len(self.chars)} exceeds the SP 800-38G maximum {MAX_RADIX}")
        index = {c: i for i, c in enumerate(self.chars)}
        if len(index) != len(self.chars):
            raise InvalidInputError("alphabet characters must be unique")
        object.__setattr__(self, "_index", index)

    @property
    def radix(self) -> int:
        return len(self.chars)

    def __contains__(self, char: object) -> bool:
        return isinstance(char, str) and char in self._index

    def to_numerals(self, text: str) -> list[int]:
        """Convert ``text`` to numerals; raises if a character is outside the alphabet."""
        try:
            return [self._index[c] for c in text]
        except KeyError:
            raise InvalidInputError("input contains a character outside the alphabet") from None

    def from_numerals(self, numerals: Sequence[int]) -> str:
        return "".join(self.chars[n] for n in numerals)


DIGITS = Alphabet(string.digits)
LOWER = Alphabet(string.ascii_lowercase)
UPPER = Alphabet(string.ascii_uppercase)
HEX_LOWER = Alphabet("0123456789abcdef")
ALNUM_LOWER = Alphabet(string.digits + string.ascii_lowercase)
ALNUM_UPPER = Alphabet(string.digits + string.ascii_uppercase)
ALNUM = Alphabet(string.digits + string.ascii_uppercase + string.ascii_lowercase)

NAMED_ALPHABETS: dict[str, Alphabet] = {
    "digits": DIGITS,
    "lower": LOWER,
    "upper": UPPER,
    "hex": HEX_LOWER,
    "alnum-lower": ALNUM_LOWER,
    "alnum-upper": ALNUM_UPPER,
    "alnum": ALNUM,
}


def alphabet_by_name(name: str) -> Alphabet:
    """Look up a built-in alphabet by name (see :data:`NAMED_ALPHABETS`)."""
    try:
        return NAMED_ALPHABETS[name]
    except KeyError:
        known = ", ".join(sorted(NAMED_ALPHABETS))
        raise InvalidInputError(f"unknown alphabet {name!r}; known: {known}") from None
