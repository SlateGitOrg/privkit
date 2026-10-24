"""Pattern recognizers: a regex proposes candidates, a validator confirms them,
and context words around the candidate raise or lower its score.

Scores are heuristic confidences in [0, 1]. The detector keeps findings whose
final score reaches its threshold (0.5 by default). Base scores below 0.5 mean
"only report this when supporting context is present" - for example a bare
nine-digit number is reported as an SSN only next to words like "ssn" or
"social security".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from privkit.pii import validators as v
from privkit.pii.model import Entity


@dataclass(frozen=True)
class PatternRecognizer:
    """A regex + validator + context recognizer for one entity type."""

    name: str
    entity: Entity
    pattern: re.Pattern[str]
    base_score: float
    validator: v.Validator | None = None
    context: frozenset[str] = frozenset()
    negative_context: frozenset[str] = frozenset()
    context_boost: float = 0.35
    negative_penalty: float = 0.4


def _words(*words: str) -> frozenset[str]:
    return frozenset(words)


_SEP = r"[ .\-]?"
_CARD_CTX = _words("card", "credit", "debit", "visa", "mastercard", "amex", "cc", "pan", "payment", "paid", "charged")
_PHONE_CTX = _words("phone", "call", "tel", "telephone", "mobile", "cell", "fax", "sms", "text", "whatsapp", "contact")
_SSN_CTX = _words("ssn", "social", "security", "ss", "taxpayer", "tin", "itin")
_ABA_CTX = _words("routing", "aba", "rtn", "transit", "ach", "wire")
_IP_CTX = _words("ip", "ipv4", "ipv6", "address", "host", "server", "client", "from", "src", "dst", "login", "connected")
_IP_NEG = _words("version", "v", "ver", "release", "build", "firmware", "sdk", "oid", "section", "chapter")
_DOB_CTX = _words("born", "dob", "birth", "birthday", "birthdate", "age")
_AADHAAR_CTX = _words("aadhaar", "aadhar", "uid", "uidai")
_NHS_CTX = _words("nhs", "patient", "chi")
_MAC_CTX = _words("mac", "device", "hardware", "ethernet", "wifi", "adapter", "nic", "bssid")
_IBAN_CTX = _words("iban", "account", "bank", "transfer", "sepa")

_MONTH = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|"
    r"Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
)

DEFAULT_RECOGNIZERS: tuple[PatternRecognizer, ...] = (
    PatternRecognizer(
        "email",
        Entity.EMAIL,
        re.compile(
            r"(?<![\w.+%-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@"
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])"
        ),
        0.9,
        v.email,
    ),
    PatternRecognizer(
        "credit_card",
        Entity.CREDIT_CARD,
        re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])"),
        0.8,
        v.credit_card,
        _CARD_CTX,
        context_boost=0.15,
    ),
    PatternRecognizer(
        "us_ssn_dashed",
        Entity.US_SSN,
        re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"),
        0.6,
        v.us_ssn,
        _SSN_CTX,
    ),
    PatternRecognizer(
        "us_ssn_spaced",
        Entity.US_SSN,
        re.compile(r"(?<![\d ])\d{3} \d{2} \d{4}(?![\d])"),
        0.4,
        v.us_ssn,
        _SSN_CTX,
    ),
    PatternRecognizer(
        "us_ssn_bare",
        Entity.US_SSN,
        re.compile(r"(?<![\d-])\d{9}(?![\d-])"),
        0.2,
        v.us_ssn,
        _SSN_CTX,
        context_boost=0.45,
    ),
    PatternRecognizer(
        "us_aba_routing",
        Entity.US_ABA_ROUTING,
        re.compile(r"(?<![\d-])\d{9}(?![\d-])"),
        0.25,
        v.us_aba_routing,
        _ABA_CTX,
        context_boost=0.5,
    ),
    PatternRecognizer(
        "phone_us_formatted",
        Entity.PHONE,
        re.compile(r"(?<![\w+])(?:\+?1[ .-]?)?(?:\(\d{3}\) ?|\d{3}[ .-])\d{3}[ .-]\d{4}(?![\w-])"),
        0.65,
        v.us_phone,
        _PHONE_CTX,
        context_boost=0.25,
    ),
    PatternRecognizer(
        "phone_us_bare",
        Entity.PHONE,
        re.compile(r"(?<![\w+])(?:\+?1)?\d{10}(?!\w)"),
        0.3,
        v.us_phone,
        _PHONE_CTX,
        context_boost=0.4,
    ),
    PatternRecognizer(
        "phone_international",
        Entity.PHONE,
        re.compile(r"(?<![\w+])\+[2-9]\d{0,2}(?:[ .-]?\(?\d{1,4}\)?){2,5}(?![\w-])"),
        0.6,
        v.intl_phone,
        _PHONE_CTX,
        context_boost=0.25,
    ),
    PatternRecognizer(
        "iban",
        Entity.IBAN,
        re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Z0-9])"),
        0.85,
        v.iban,
        _IBAN_CTX,
        context_boost=0.1,
    ),
    PatternRecognizer(
        "ipv4",
        Entity.IP_ADDRESS,
        re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)"),
        0.6,
        v.ipv4,
        _IP_CTX,
        _IP_NEG,
        context_boost=0.25,
        negative_penalty=0.45,
    ),
    PatternRecognizer(
        "ipv6",
        Entity.IP_ADDRESS,
        re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"),
        0.75,
        v.ipv6,
        _IP_CTX,
        context_boost=0.15,
    ),
    PatternRecognizer(
        "mac_address",
        Entity.MAC_ADDRESS,
        re.compile(
            r"(?<![\w:.-])(?:[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
            r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![\w:.-])"
        ),
        0.7,
        v.mac_address,
        _MAC_CTX,
        context_boost=0.2,
    ),
    PatternRecognizer(
        "in_aadhaar",
        Entity.IN_AADHAAR,
        re.compile(r"(?<![\d-])[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?![\d-])"),
        0.35,
        v.in_aadhaar,
        _AADHAAR_CTX,
        context_boost=0.45,
    ),
    PatternRecognizer(
        "uk_nhs",
        Entity.UK_NHS,
        re.compile(r"(?<![\d-])\d{3}([ -]?)\d{3}\1\d{4}(?![\d-])"),
        0.3,
        v.uk_nhs,
        _NHS_CTX,
        context_boost=0.5,
    ),
    PatternRecognizer(
        "date_of_birth",
        Entity.DATE_OF_BIRTH,
        re.compile(
            r"(?<![\w/-])(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4}|\d{1,2} " + _MONTH + r",? \d{4}|"
            + _MONTH + r" \d{1,2},? \d{4})(?![\w/-])"
        ),
        0.15,
        v.date_of_birth,
        _DOB_CTX,
        context_boost=0.5,
    ),
)
