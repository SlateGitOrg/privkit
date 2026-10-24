"""Validators: decide whether a regex candidate really is the entity.

Each validator receives the raw matched text and returns the length of the
accepted prefix (normally the full length) or ``None`` to reject the candidate.
Returning a shorter length lets a validator trim over-greedy matches, which the
IBAN validator uses to drop trailing words that happen to look like a group.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from collections.abc import Callable

from privkit.checksums import aba_valid, iban_mod97, luhn_valid, nhs_valid, verhoeff_valid

Validator = Callable[[str], int | None]

_NON_DIGIT = re.compile(r"\D")


def digits_only(text: str) -> str:
    return _NON_DIGIT.sub("", text)


def _accept(ok: bool, text: str) -> int | None:
    return len(text) if ok else None


# --- payment cards ---------------------------------------------------------

def _iin_matches(number: str) -> bool:
    """Issuer identification number (prefix) and length rules of the major networks."""
    n = len(number)
    p2, p3, p4, p6 = int(number[:2]), int(number[:3]), int(number[:4]), int(number[:6])
    rules = (
        number[0] == "4" and n in (13, 16, 19),  # Visa
        (51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16,  # Mastercard
        p2 in (34, 37) and n == 15,  # American Express
        (p4 == 6011 or p2 == 65 or 644 <= p3 <= 649 or 622126 <= p6 <= 622925) and 16 <= n <= 19,  # Discover
        3528 <= p4 <= 3589 and 16 <= n <= 19,  # JCB
        (300 <= p3 <= 305 or p2 in (36, 38, 39) or p4 == 3095) and 14 <= n <= 19,  # Diners
        p2 == 62 and 16 <= n <= 19,  # UnionPay
        (p4 in (5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763)) and 12 <= n <= 19,  # Maestro
    )
    return any(rules)


def credit_card(text: str) -> int | None:
    number = digits_only(text)
    if not 13 <= len(number) <= 19 or len(set(number)) == 1:
        return None
    return _accept(luhn_valid(number) and _iin_matches(number), text)


# --- US identifiers ----------------------------------------------------------

_SSA_INVALID = frozenset({"078051120", "219099999"})  # numbers the SSA voided after publication


def us_ssn(text: str) -> int | None:
    number = digits_only(text)
    if len(number) != 9 or number in _SSA_INVALID:
        return None
    area, group, serial = int(number[:3]), int(number[3:5]), int(number[5:])
    ok = 0 < area < 900 and area != 666 and group != 0 and serial != 0
    return _accept(ok, text)


def _aba_prefix_ok(number: str) -> bool:
    prefix = int(number[:2])
    return prefix <= 12 or 21 <= prefix <= 32 or 61 <= prefix <= 72 or prefix == 80


def us_aba_routing(text: str) -> int | None:
    number = digits_only(text)
    return _accept(len(number) == 9 and _aba_prefix_ok(number) and aba_valid(number), text)


def us_phone(text: str) -> int | None:
    number = digits_only(text)
    if len(number) == 11 and number[0] == "1":
        number = number[1:]
    if len(number) != 10:
        return None
    area, exchange = number[:3], number[3:6]
    ok = area[0] not in "01" and exchange[0] not in "01" and area[1:] != "11" and exchange[1:] != "11"
    return _accept(ok and len(set(number)) > 2, text)


def intl_phone(text: str) -> int | None:
    number = digits_only(text)
    return _accept(8 <= len(number) <= 15, text)


# --- other national identifiers ----------------------------------------------

def in_aadhaar(text: str) -> int | None:
    number = digits_only(text)
    return _accept(len(number) == 12 and number[0] not in "01" and verhoeff_valid(number), text)


def uk_nhs(text: str) -> int | None:
    number = digits_only(text)
    return _accept(len(set(number)) > 1 and nhs_valid(number), text)


# ISO 13616 registry lengths for the countries privkit validates.
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AT": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "CH": 21, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27,
    "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27, "KW": 30, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "MC": 27, "MT": 31, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PT": 25,
    "QA": 29, "RO": 24, "SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TR": 26,
}  # fmt: skip


def iban(text: str) -> int | None:
    expected = IBAN_LENGTHS.get(text[:2])
    if expected is None:
        return None
    count = 0
    for i, ch in enumerate(text):
        if ch.isalnum():
            count += 1
            if count == expected:
                compact = re.sub(r"[^A-Z0-9]", "", text[: i + 1])
                return i + 1 if iban_mod97(compact) == 1 else None
    return None


# --- network identifiers -------------------------------------------------------

def ipv4(text: str) -> int | None:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return None
    return len(text)


def ipv6(text: str) -> int | None:
    if text.count(":") < 2:
        return None
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return None
    return len(text)


def mac_address(text: str) -> int | None:
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", text)
    return _accept(len(hexdigits) == 12 and len(set(hexdigits.lower())) > 1, text)


# --- dates -------------------------------------------------------------------

_MONTHS = {
    m: i + 1
    for i, names in enumerate(
        [
            ("jan", "january"), ("feb", "february"), ("mar", "march"), ("apr", "april"),
            ("may",), ("jun", "june"), ("jul", "july"), ("aug", "august"),
            ("sep", "sept", "september"), ("oct", "october"), ("nov", "november"), ("dec", "december"),
        ]
    )
    for m in names
}  # fmt: skip


def parse_date(text: str) -> dt.date | None:
    """Parse the date formats the DOB recognizer matches; None when not a real date."""
    s = text.strip().rstrip(".").replace(",", "")
    try:
        if m := re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s):
            return dt.date(int(m[1]), int(m[2]), int(m[3]))
        if m := re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", s):
            return dt.date(int(m[3]), int(m[1]), int(m[2]))
        if m := re.fullmatch(r"(\d{1,2}) ([A-Za-z]+) (\d{4})", s):
            month = _MONTHS.get(m[2].lower())
            return dt.date(int(m[3]), month, int(m[1])) if month else None
        if m := re.fullmatch(r"([A-Za-z]+) (\d{1,2}) (\d{4})", s):
            month = _MONTHS.get(m[1].lower())
            return dt.date(int(m[3]), month, int(m[2])) if month else None
    except ValueError:
        return None
    return None


def date_of_birth(text: str) -> int | None:
    date = parse_date(text)
    return _accept(date is not None and 1900 <= date.year <= dt.date.today().year, text)


def email(text: str) -> int | None:
    local, _, domain = text.partition("@")
    ok = ".." not in text and not local.endswith(".") and len(local) <= 64 and "." in domain
    return _accept(ok, text)
