"""Check-digit algorithms used to validate (and to generate) identifiers.

All functions take the identifier's digits/characters with separators already
removed and are O(n) in the identifier length.
"""

from __future__ import annotations

from privkit.errors import InvalidInputError


def _digits(text: str) -> list[int]:
    if not text.isascii() or not text.isdigit():
        raise InvalidInputError("expected an ASCII digit string")
    return [ord(c) - 48 for c in text]


def luhn_check_digit(body: str) -> int:
    """Check digit that makes ``body + digit`` pass the Luhn (mod 10) test."""
    total = 0
    for i, d in enumerate(reversed(_digits(body))):
        if i % 2 == 0:  # positions that get doubled once the check digit is appended
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def luhn_valid(number: str) -> bool:
    if len(number) < 2 or not number.isascii() or not number.isdigit():
        return False
    return luhn_check_digit(number[:-1]) == int(number[-1])


def iban_mod97(iban: str) -> int:
    """ISO 13616 / ISO 7064 MOD 97-10 remainder; a valid IBAN gives 1."""
    text = iban.upper()
    if not text.isascii() or not text.isalnum() or len(text) < 5:
        raise InvalidInputError("IBAN must be at least 5 ASCII alphanumeric characters")
    rearranged = text[4:] + text[:4]
    remainder = 0
    for ch in rearranged:
        value = int(ch) if ch.isdigit() else ord(ch) - 55  # A=10 ... Z=35
        remainder = (remainder * (100 if value > 9 else 10) + value) % 97
    return remainder


def iban_check_digits(country: str, bban: str) -> str:
    """The two check digits for ``country`` + ``bban`` (used to build valid test IBANs)."""
    remainder = iban_mod97(country + "00" + bban)
    return f"{98 - remainder:02d}"


def aba_valid(routing: str) -> bool:
    """ABA routing-number checksum: 3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) == 0 mod 10."""
    if len(routing) != 9 or not routing.isascii() or not routing.isdigit():
        return False
    d = _digits(routing)
    total = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
    return total % 10 == 0


def aba_check_digit(first8: str) -> int:
    d = _digits(first8)
    if len(d) != 8:
        raise InvalidInputError("expected 8 digits")
    partial = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5])
    return (10 - partial % 10) % 10


# Verhoeff dihedral-group tables (used by Aadhaar).
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(number: str) -> bool:
    if not number or not number.isascii() or not number.isdigit():
        return False
    c = 0
    for i, d in enumerate(reversed(_digits(number))):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


def verhoeff_check_digit(body: str) -> int:
    c = 0
    for i, d in enumerate(reversed(_digits(body))):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][d]]
    return _VERHOEFF_INV[c]


def nhs_check_digit(first9: str) -> int | None:
    """NHS number modulus-11 check digit, or ``None`` when the body is unusable (remainder 10)."""
    d = _digits(first9)
    if len(d) != 9:
        raise InvalidInputError("expected 9 digits")
    total = sum(digit * (10 - i) for i, digit in enumerate(d))
    check = 11 - total % 11
    if check == 11:
        return 0
    if check == 10:
        return None
    return check


def nhs_valid(number: str) -> bool:
    if len(number) != 10 or not number.isascii() or not number.isdigit():
        return False
    check = nhs_check_digit(number[:9])
    return check is not None and check == int(number[9])
