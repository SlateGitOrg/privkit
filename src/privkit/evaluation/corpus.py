"""Synthetic, labeled PII corpus for detector evaluation.

Two disjoint template pools exist: ``dev`` (used while tuning recognizers and
context words) and ``test`` (held out; written with different phrasing and
context cues, and drawing names/cities from disjoint pools). Every generated
identifier is *valid by construction* (Luhn, mod-97, Verhoeff, ...), and each
pool also plants *hard negatives*: checksum-invalid cards and IBANs, impossible
SSNs, version strings shaped like IPv4 addresses, unlabeled 9-digit order
numbers and non-birth dates.

All data is fabricated; no real person's data is involved. Because generator
and detector are written by the same author, scores here are an optimistic
upper bound for real text - see the README's Limitations section.
"""

from __future__ import annotations

import ipaddress
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from privkit.checksums import (
    aba_check_digit,
    iban_check_digits,
    luhn_check_digit,
    nhs_check_digit,
    verhoeff_check_digit,
)

Split = Literal["dev", "test"]


@dataclass(frozen=True)
class Span:
    entity: str
    start: int
    end: int


@dataclass(frozen=True)
class Document:
    doc_id: str
    text: str
    spans: tuple[Span, ...]


_FIRST = [
    "Maria", "James", "Aisha", "Wei", "Olivia", "Rahul", "Sofia", "Daniel", "Priya", "Lucas", "Emma",
    "Mateo", "Hannah", "Kenji", "Chloe", "Omar", "Grace", "Ivan", "Zara", "Ethan", "Leila", "Noah",
    "Amara", "Felix", "Nina", "Samuel", "Mei", "Arjun", "Clara", "Diego", "Fatima", "Oscar",
]  # fmt: skip
_LAST = [
    "Gonzalez", "Smith", "Khan", "Zhang", "Johnson", "Sharma", "Rossi", "Miller", "Patel", "Silva",
    "Brown", "Lopez", "Schmidt", "Tanaka", "Martin", "Haddad", "Wilson", "Petrov", "Ahmed", "Clarke",
    "Nguyen", "Davis", "Okafor", "Weber", "Moreau", "Taylor", "Chen", "Iyer", "Fischer", "Ramos",
]  # fmt: skip
_CITIES = [
    "Denver", "Chicago", "London", "Berlin", "Madrid", "Toronto", "Mumbai", "Sydney", "Boston",
    "Dublin", "Lisbon", "Seattle", "Paris", "Austin", "Vienna", "Atlanta", "Oslo", "Phoenix",
]  # fmt: skip
_DOMAINS = ["example.com", "mail.example.org", "corp.example.net", "example.co.uk", "inbox.example.io"]

# Each template mixes labeled slots ({EMAIL}) and unlabeled hard-negative slots ({NEG_CARD}).
DEV_TEMPLATES = [
    "Hi team, please update the card on file for {PERSON} to {CARD} before Friday.",
    "Customer {PERSON} called from {PHONE} about a duplicate charge.",
    "You can reach me at {EMAIL} or on my mobile {PHONE}.",
    "SSN: {SSN} (verified against the W-2).",
    "Her social security number is {SSN_BARE} per the intake form.",
    "Wire funds to IBAN {IBAN}, reference invoice {ORDER9}.",
    "Login from IP {IPV4} was blocked after five attempts.",
    "We upgraded the agent to version {VERSION} last night.",
    "Payment declined for card {NEG_CARD}; customer will retry with {CARD}.",
    "Routing number {ABA} and account ending 4421 were provided by {PERSON}.",
    "Date of birth: {DOB}. Patient lives in {CITY}.",
    "Device MAC {MAC} connected to the guest network.",
    "Aadhaar {AADHAAR} was submitted for KYC by {PERSON}.",
    "NHS number {NHS} recorded at the {CITY} clinic.",
    "Order {ORDER9} shipped to {CITY} on {DATE}.",
    "Host {IPV6} answered the health check.",
    "Please email {EMAIL} the receipt; the meeting is on {DATE}.",
    "The SSN {NEG_SSN} on the form is not valid, please re-check.",
    "IBAN {NEG_IBAN} failed validation; bank asked for a corrected IBAN.",
    "{PERSON} moved from {CITY} and was born {DOB}.",
    "Call +1 support line or text {PHONE} for help.",
    "Ticket {ORDER9}: user {EMAIL} cannot log in from {IPV4}.",
    "Meeting moved to 10:30:15 UTC; dial-in code 4411 2234.",
    "Total due: $1,204.50 for SKU 4000-1234-5678.",
    "The card ending in 4242 was charged twice.",
    "Contact: {EMAIL}\nPhone: {PHONE}\nSSN: {SSN}",
    "\"{EMAIL}\" bounced; resend to <{EMAIL}>.",
]  # fmt: skip
TEST_TEMPLATES = [
    "Refund approved. Charged to {CARD} (cardholder {PERSON}).",
    "Contact details - tel: {PHONE}, e-mail: {EMAIL}.",
    "Applicant SSN {SSN}; employer confirmed the start date of {DATE}.",
    "Taxpayer id (ssn) {SSN_BARE} appears on page two.",
    "Bank transfer to account {IBAN} is scheduled.",
    "Firewall denied traffic from source {IPV4} to port 443.",
    "Release notes for build {VERSION} are attached.",
    "Card number {NEG_CARD} looks mistyped; the customer then gave {CARD}.",
    "ACH routing {ABA} belongs to the payroll account of {PERSON}.",
    "DOB {DOB}, admitted in {CITY}.",
    "Our records show {PERSON} was born on {DOB}.",
    "Ethernet adapter {MAC} is on the blocklist.",
    "UIDAI number {AADHAAR} was linked to the account.",
    "Patient NHS {NHS}, referred by Dr. {PERSON}.",
    "Invoice {ORDER9} was paid on {DATE} from {CITY}.",
    "Client {IPV6} timed out twice.",
    "Forward the statement to {EMAIL} and cc {EMAIL}.",
    "Rejected form: SSN {NEG_SSN} is impossible.",
    "The IBAN {NEG_IBAN} has a bad check digit.",
    "Ring {PERSON} on {PHONE} after 5pm.",
    "Shipment {ORDER9} weighed 12.5 kg and left {CITY}.",
    "Server src {IPV4} -> dst {IPV4} flagged by IDS.",
    "Uptime 99.95% between 12:00:01 and 13:00:00; build 4.4.0.12-rc deployed.",
    "Amount $3,450.00 charged, last four 1881.",
    "From: {EMAIL}\nTel {PHONE}\nIBAN: {IBAN}",
    "('{PERSON}', '{SSN}', '{CARD}')",
    "Coordinates 40.7128, -74.0060 near {CITY}.",
]  # fmt: skip

_SLOT = re.compile(r"\{([A-Z0-9_]+)\}")


class SyntheticValues:
    """Generators for valid-by-construction identifiers and hard negatives (all fabricated)."""

    def __init__(self, rng: random.Random, split: Split) -> None:
        self.r = rng
        parity = 0 if split == "dev" else 1
        self.first = _FIRST[parity::2]
        self.last = _LAST[parity::2]
        self.cities = _CITIES[parity::2]

    def digits(self, n: int) -> str:
        return "".join(self.r.choice("0123456789") for _ in range(n))

    def _group_card(self, number: str) -> str:
        sep = self.r.choice([" ", "-", ""])
        if len(number) == 15:
            return sep.join([number[:4], number[4:10], number[10:]])
        return sep.join(number[i : i + 4] for i in range(0, len(number), 4))

    def card(self) -> str:
        kind = self.r.choice(["visa", "mc", "amex", "discover"])
        prefix, length = {
            "visa": ("4", 16),
            "mc": (str(self.r.randint(51, 55)), 16),
            "amex": (self.r.choice(["34", "37"]), 15),
            "discover": ("6011", 16),
        }[kind]
        body = prefix + self.digits(length - len(prefix) - 1)
        return self._group_card(body + str(luhn_check_digit(body)))

    def neg_card(self) -> str:
        body = "4" + self.digits(14)
        return self._group_card(body + str((luhn_check_digit(body) + 1) % 10))

    def _ssn_digits(self) -> str:
        area = self.r.choice([a for a in range(1, 900) if a != 666])
        return f"{area:03d}{self.r.randint(1, 99):02d}{self.r.randint(1, 9999):04d}"

    def ssn(self) -> str:
        d = self._ssn_digits()
        return f"{d[:3]}-{d[3:5]}-{d[5:]}"

    def ssn_bare(self) -> str:
        return self._ssn_digits()

    def neg_ssn(self) -> str:
        area = self.r.choice(["000", "666", str(self.r.randint(900, 999))])
        return f"{area}-{self.r.randint(1, 99):02d}-{self.r.randint(1, 9999):04d}"

    def phone(self) -> str:
        if self.r.random() < 0.25:
            return self.r.choice(["+44 20 7946 ", "+49 30 9018 ", "+91 98765 ", "+33 1 4268 "]) + self.digits(4)

        def part3() -> str:
            while True:
                p = str(self.r.randint(2, 9)) + self.digits(2)
                if p[1:] != "11":
                    return p

        area, exch, line = part3(), part3(), self.digits(4)
        fmt = self.r.choice(["({a}) {e}-{l}", "{a}-{e}-{l}", "{a}.{e}.{l}", "+1 {a} {e} {l}", "+1-{a}-{e}-{l}"])
        return fmt.format(a=area, e=exch, l=line)

    def email(self) -> str:
        f, last = self.r.choice(self.first).lower(), self.r.choice(self.last).lower()
        local = self.r.choice([f"{f}.{last}", f"{f[0]}{last}", f"{f}_{last}{self.r.randint(1, 99)}", f"{last}.{f}"])
        return f"{local}@{self.r.choice(_DOMAINS)}"

    def _bban(self, country: str) -> str:
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if country == "DE":
            return self.digits(18)
        if country == "GB":
            return "".join(self.r.choice(letters) for _ in range(4)) + self.digits(14)
        if country == "FR":
            return self.digits(23)
        if country == "ES":
            return self.digits(20)
        if country == "NL":
            return "".join(self.r.choice(letters) for _ in range(4)) + self.digits(10)
        return self.r.choice(letters) + self.digits(22)  # IT

    def _format_iban(self, compact: str) -> str:
        if self.r.random() < 0.7:
            return " ".join(compact[i : i + 4] for i in range(0, len(compact), 4))
        return compact

    def iban(self) -> str:
        country = self.r.choice(["DE", "GB", "FR", "ES", "NL", "IT"])
        bban = self._bban(country)
        return self._format_iban(country + iban_check_digits(country, bban) + bban)

    def neg_iban(self) -> str:
        country = self.r.choice(["DE", "GB", "NL"])
        bban = self._bban(country)
        good = int(iban_check_digits(country, bban))
        bad = f"{(good + self.r.randint(1, 50)) % 97 + 2:02d}"
        if bad == f"{good:02d}":
            bad = f"{(good % 97) + 1:02d}"
        return self._format_iban(country + bad + bban)

    def ipv4(self) -> str:
        while True:
            addr = ipaddress.IPv4Address(self.r.getrandbits(32))
            if not (addr.is_multicast or addr.is_reserved or addr.is_unspecified or str(addr).startswith("0.")):
                return str(addr)

    def ipv6(self) -> str:
        groups = [self.r.getrandbits(16) for _ in range(8)]
        if self.r.random() < 0.5:
            groups[2:5] = [0, 0, 0]
        return str(ipaddress.IPv6Address(b"".join(g.to_bytes(2, "big") for g in groups)))

    def version(self) -> str:
        return ".".join(str(self.r.randint(0, 20)) for _ in range(4))

    def mac(self) -> str:
        octets = [f"{self.r.getrandbits(8):02x}" for _ in range(6)]
        text = self.r.choice([":", "-"]).join(octets)
        return text.upper() if self.r.random() < 0.5 else text

    def aba(self) -> str:
        prefix = f"{self.r.choice([*range(1, 13), *range(21, 33), *range(61, 73)]):02d}"
        first8 = prefix + self.digits(6)
        return first8 + str(aba_check_digit(first8))

    def order9(self) -> str:
        return str(self.r.randint(100_000_000, 999_999_999))

    def aadhaar(self) -> str:
        body = str(self.r.randint(2, 9)) + self.digits(10)
        n = body + str(verhoeff_check_digit(body))
        return " ".join([n[:4], n[4:8], n[8:]])

    def nhs(self) -> str:
        while True:
            body = self.digits(9)
            check = nhs_check_digit(body)
            if check is not None:
                n = body + str(check)
                return " ".join([n[:3], n[3:6], n[6:]])

    def _date(self, lo: int, hi: int) -> str:
        y, m, d = self.r.randint(lo, hi), self.r.randint(1, 12), self.r.randint(1, 28)
        months = ["January", "February", "March", "April", "May", "June", "July", "August",
                  "September", "October", "November", "December"]  # fmt: skip
        return self.r.choice(
            [f"{y:04d}-{m:02d}-{d:02d}", f"{m}/{d}/{y}", f"{d} {months[m - 1]} {y}", f"{months[m - 1]} {d}, {y}"]
        )

    def dob(self) -> str:
        return self._date(1940, 2005)

    def date(self) -> str:
        return self._date(2019, 2025)

    def person(self) -> str:
        return f"{self.r.choice(self.first)} {self.r.choice(self.last)}"

    def city(self) -> str:
        return self.r.choice(self.cities)


# slot -> (entity label or None for an unlabeled negative, generator method name)
_SLOTS: dict[str, tuple[str | None, str]] = {
    "CARD": ("CREDIT_CARD", "card"),
    "NEG_CARD": (None, "neg_card"),
    "SSN": ("US_SSN", "ssn"),
    "SSN_BARE": ("US_SSN", "ssn_bare"),
    "NEG_SSN": (None, "neg_ssn"),
    "PHONE": ("PHONE", "phone"),
    "EMAIL": ("EMAIL", "email"),
    "IBAN": ("IBAN", "iban"),
    "NEG_IBAN": (None, "neg_iban"),
    "IPV4": ("IP_ADDRESS", "ipv4"),
    "IPV6": ("IP_ADDRESS", "ipv6"),
    "VERSION": (None, "version"),
    "MAC": ("MAC_ADDRESS", "mac"),
    "ABA": ("US_ABA_ROUTING", "aba"),
    "ORDER9": (None, "order9"),
    "AADHAAR": ("IN_AADHAAR", "aadhaar"),
    "NHS": ("UK_NHS", "nhs"),
    "DOB": ("DATE_OF_BIRTH", "dob"),
    "DATE": (None, "date"),
    "PERSON": ("PERSON", "person"),
    "CITY": ("LOCATION", "city"),
}


def _fill(template: str, values: SyntheticValues) -> tuple[str, list[Span]]:
    out: list[str] = []
    spans: list[Span] = []
    cursor = 0
    length = 0
    for match in _SLOT.finditer(template):
        literal = template[cursor : match.start()]
        out.append(literal)
        length += len(literal)
        label, method = _SLOTS[match.group(1)]
        generator: Callable[[], str] = getattr(values, method)
        value = generator()
        if label is not None:
            spans.append(Span(label, length, length + len(value)))
        out.append(value)
        length += len(value)
        cursor = match.end()
    out.append(template[cursor:])
    return "".join(out), spans


def generate_corpus(split: Split, n_docs: int, seed: int) -> list[Document]:
    """Generate ``n_docs`` documents of 1-3 sentences from the ``split`` template pool."""
    if split not in ("dev", "test"):
        raise ValueError("split must be 'dev' or 'test'")
    rng = random.Random(f"privkit-corpus|{split}|{seed}")
    values = SyntheticValues(rng, split)
    templates = DEV_TEMPLATES if split == "dev" else TEST_TEMPLATES
    docs = []
    for i in range(n_docs):
        text, spans = "", list[Span]()
        for _ in range(rng.randint(1, 3)):
            sentence, sentence_spans = _fill(rng.choice(templates), values)
            offset = len(text) + (1 if text else 0)
            text = f"{text} {sentence}" if text else sentence
            spans.extend(Span(s.entity, s.start + offset, s.end + offset) for s in sentence_spans)
        docs.append(Document(f"{split}-{seed}-{i:05d}", text, tuple(spans)))
    return docs
