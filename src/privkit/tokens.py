"""Vaultless, reversible, format-preserving tokenization.

A :class:`Tokenizer` turns a sensitive value into a token of the same shape
(digits stay digits, separators stay put, an email keeps its domain) using FF1 or
FF3-1 under a key derived per policy from one master key. Detokenization is the
inverse permutation, so no token vault (lookup table) is needed.

Design notes:

* The tweak binds the policy name and any characters kept in the clear (for
  example the last four digits of a card), so two cards that share their last
  four digits still use different permutations of the encrypted middle part.
* Domains smaller than one million values are refused, following SP 800-38G
  Rev. 1; small domains are trivially enumerable and FPE gives little there.
* Tokens are deterministic: equal inputs give equal tokens under one key and
  policy. That preserves joins, and it is also an equality leak - see
  ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from privkit.checksums import luhn_check_digit
from privkit.errors import ConfigurationError, DomainTooSmallError, InvalidInputError
from privkit.fpe import (
    ALNUM,
    ALNUM_UPPER,
    DIGITS,
    HEX_LOWER,
    MIN_DOMAIN,
    Algorithm,
    Alphabet,
    FormatPreservingCipher,
)
from privkit.keys import derive_key

logger = logging.getLogger(__name__)


class LuhnMode(StrEnum):
    """How the trailing check digit of a Luhn-protected number is treated."""

    NONE = "none"  # the check digit is encrypted like any other digit
    VALID = "valid"  # tokens pass Luhn (drop-in for systems that validate PANs)
    INVALID = "invalid"  # tokens deliberately fail Luhn, so they never look like real PANs


class Codec(StrEnum):
    CHARS = "chars"  # encrypt the characters that belong to the policy alphabet
    IP = "ip"  # encrypt an IPv4/IPv6 address as octets/hextets; output is a valid address


class Normalize(StrEnum):
    NONE = "none"
    LOWER = "lower"
    UPPER = "upper"


@dataclass(frozen=True)
class TokenPolicy:
    """How values of one field or entity type are tokenized."""

    name: str
    alphabet: Alphabet = DIGITS
    algorithm: Algorithm = Algorithm.FF1
    codec: Codec = Codec.CHARS
    keep_prefix: int = 0
    keep_suffix: int = 0
    luhn: LuhnMode = LuhnMode.NONE
    span_pattern: str | None = None
    normalize: Normalize = Normalize.NONE
    _span_re: re.Pattern[str] | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ConfigurationError("policy name must be non-empty")
        if self.keep_prefix < 0 or self.keep_suffix < 0:
            raise ConfigurationError("keep_prefix/keep_suffix must be non-negative")
        if self.luhn is not LuhnMode.NONE:
            if self.alphabet != DIGITS:
                raise ConfigurationError("Luhn handling requires the digits alphabet")
            if self.keep_suffix:
                raise ConfigurationError("Luhn handling conflicts with keep_suffix (check digit is last)")
        if self.codec is Codec.IP and (self.keep_suffix or self.span_pattern or self.luhn is not LuhnMode.NONE):
            raise ConfigurationError("the ip codec only supports keep_prefix")
        span = re.compile(self.span_pattern) if self.span_pattern else None
        if span is not None and span.groups != 1:
            raise ConfigurationError("span_pattern must have exactly one capture group")
        object.__setattr__(self, "_span_re", span)

    def region(self, value: str) -> tuple[int, int]:
        if self._span_re is None:
            return 0, len(value)
        match = self._span_re.search(value)
        if match is None:
            raise InvalidInputError(f"value does not match the span pattern of policy {self.name!r}")
        return match.span(1)


DEFAULT_POLICIES: dict[str, TokenPolicy] = {
    p.name: p
    for p in (
        TokenPolicy("CREDIT_CARD", DIGITS, keep_suffix=4),
        TokenPolicy("US_SSN", DIGITS),
        TokenPolicy("PHONE", DIGITS),
        TokenPolicy("US_ABA_ROUTING", DIGITS),
        TokenPolicy("IN_AADHAAR", DIGITS),
        TokenPolicy("UK_NHS", DIGITS),
        # Dates such as "August 7, 1962" hold only 5 digits (< 10^6), so letters are encrypted too.
        TokenPolicy("DATE_OF_BIRTH", ALNUM),
        TokenPolicy("EMAIL", ALNUM, span_pattern=r"^([^@]+)@"),
        # Also encrypts the domain labels (keeps the TLD): works for very short local parts.
        TokenPolicy("EMAIL_FULL", ALNUM, span_pattern=r"^(.+)\.[A-Za-z]{2,24}$"),
        TokenPolicy("IBAN", ALNUM_UPPER, keep_prefix=4, normalize=Normalize.UPPER),
        TokenPolicy("MAC_ADDRESS", HEX_LOWER, normalize=Normalize.LOWER),
        TokenPolicy("IP_ADDRESS", codec=Codec.IP),
        TokenPolicy("PERSON", ALNUM),
        TokenPolicy("LOCATION", ALNUM),
    )
}


def _tweak(policy: TokenPolicy, kept: str, size: int) -> bytes:
    digest = hashlib.sha256(f"privkit-tweak|{policy.name}|{kept}".encode()).digest()
    return digest[:size]


class Tokenizer:
    """Reversible format-preserving tokenizer.

    >>> t = Tokenizer(bytes(32))
    >>> token = t.tokenize("4111 1111 1111 1111", "CREDIT_CARD")
    >>> token.endswith("1111"), len(token) == 19, t.detokenize(token, "CREDIT_CARD")
    (True, True, '4111 1111 1111 1111')
    """

    def __init__(self, master_key: bytes, policies: Mapping[str, TokenPolicy] | None = None) -> None:
        self._master = master_key
        self.policies: dict[str, TokenPolicy] = dict(DEFAULT_POLICIES if policies is None else policies)
        self._ciphers: dict[tuple[str, int, Algorithm], FormatPreservingCipher] = {}
        derive_key(master_key, "privkit/v1/self-test")  # fail fast on a bad key

    def policy(self, policy: str | TokenPolicy) -> TokenPolicy:
        if isinstance(policy, TokenPolicy):
            return policy
        try:
            return self.policies[policy]
        except KeyError:
            raise ConfigurationError(f"no token policy named {policy!r}") from None

    def _cipher(self, policy: TokenPolicy, alphabet: Alphabet) -> FormatPreservingCipher:
        cache_key = (policy.name, alphabet.radix, policy.algorithm)
        cipher = self._ciphers.get(cache_key)
        if cipher is None:
            key = derive_key(self._master, f"privkit/v1/token/{policy.algorithm.value}/{policy.name}")
            cipher = FormatPreservingCipher(key, alphabet, policy.algorithm)
            self._ciphers[cache_key] = cipher
        return cipher

    def tokenize(self, value: str, policy: str | TokenPolicy) -> str:
        """Return the format-preserving token for ``value``."""
        pol = self.policy(policy)
        if pol.codec is Codec.IP:
            return self._ip(value, pol, encrypt=True)
        return self._chars(value, pol, encrypt=True)

    def detokenize(self, token: str, policy: str | TokenPolicy) -> str:
        """Invert :meth:`tokenize` (requires the same master key and policy)."""
        pol = self.policy(policy)
        if pol.codec is Codec.IP:
            return self._ip(token, pol, encrypt=False)
        return self._chars(token, pol, encrypt=False)

    # -- character codec -------------------------------------------------
    def _chars(self, value: str, pol: TokenPolicy, *, encrypt: bool) -> str:
        if encrypt and pol.normalize is Normalize.LOWER:
            value = value.lower()
        elif encrypt and pol.normalize is Normalize.UPPER:
            value = value.upper()
        start, end = pol.region(value)
        positions = [i for i in range(start, end) if value[i] in pol.alphabet]
        check_pos: int | None = None
        if pol.luhn is not LuhnMode.NONE:
            if len(positions) < 2:
                raise InvalidInputError("value too short for Luhn handling")
            check_pos = positions.pop()
            if encrypt:
                body = "".join(value[i] for i in positions)
                if luhn_check_digit(body) != int(value[check_pos]):
                    raise InvalidInputError("value fails the Luhn check; cannot preserve it reversibly")
        if pol.keep_prefix + pol.keep_suffix >= len(positions):
            raise DomainTooSmallError(f"nothing left to encrypt under policy {pol.name!r}")
        kept_head = positions[: pol.keep_prefix]
        kept_tail = positions[len(positions) - pol.keep_suffix :] if pol.keep_suffix else []
        work = positions[pol.keep_prefix : len(positions) - pol.keep_suffix]
        if pol.alphabet.radix ** len(work) < MIN_DOMAIN:
            raise DomainTooSmallError(
                f"policy {pol.name!r}: {len(work)} characters over radix {pol.alphabet.radix} "
                f"is below the {MIN_DOMAIN:,}-value minimum domain"
            )
        kept = "".join(value[i] for i in kept_head) + "|" + "".join(value[i] for i in kept_tail)
        cipher = self._cipher(pol, pol.alphabet)
        tweak = _tweak(pol, kept, 16 if pol.algorithm is Algorithm.FF1 else 7)
        segment = "".join(value[i] for i in work)
        if len(segment) > cipher.maxlen:
            raise InvalidInputError(f"value too long for policy {pol.name!r}")
        out_segment = cipher.encrypt(segment, tweak) if encrypt else cipher.decrypt(segment, tweak)
        chars = list(value)
        for i, ch in zip(work, out_segment, strict=True):
            chars[i] = ch
        if check_pos is not None:
            body = "".join(chars[i] for i in positions)
            digit = luhn_check_digit(body)
            if encrypt and pol.luhn is LuhnMode.INVALID:
                digit = (digit + 1) % 10
            chars[check_pos] = str(digit)
        return "".join(chars)

    # -- IP codec ---------------------------------------------------------
    def _ip(self, value: str, pol: TokenPolicy, *, encrypt: bool) -> str:
        try:
            addr = ipaddress.ip_address(value.strip())
        except ValueError:
            raise InvalidInputError("value is not an IP address") from None
        if addr.version == 4:
            radix, parts = 256, list(addr.packed)
        else:
            packed = addr.packed
            radix, parts = 1 << 16, [int.from_bytes(packed[i : i + 2], "big") for i in range(0, 16, 2)]
        keep = pol.keep_prefix
        work = parts[keep:]
        if keep >= len(parts) or radix ** len(work) < MIN_DOMAIN:
            raise DomainTooSmallError(f"policy {pol.name!r}: too few address parts left to encrypt")
        alphabet = _radix_alphabet(radix)
        cipher = self._cipher(pol, alphabet)
        tweak = _tweak(pol, f"v{addr.version}:{parts[:keep]}", 16 if pol.algorithm is Algorithm.FF1 else 7)
        text = alphabet.from_numerals(work)
        out = alphabet.to_numerals(cipher.encrypt(text, tweak) if encrypt else cipher.decrypt(text, tweak))
        parts = parts[:keep] + out
        if addr.version == 4:
            return str(ipaddress.IPv4Address(bytes(parts)))
        return str(ipaddress.IPv6Address(b"".join(p.to_bytes(2, "big") for p in parts)))


_RADIX_ALPHABETS: dict[int, Alphabet] = {}


def _radix_alphabet(radix: int) -> Alphabet:
    """A private alphabet of ``radix`` code points, used to route raw numerals through the cipher."""
    alphabet = _RADIX_ALPHABETS.get(radix)
    if alphabet is None:
        # Code points from U+10000 upward are never surrogates and are all distinct.
        alphabet = Alphabet("".join(chr(0x10000 + i) for i in range(radix)))
        _RADIX_ALPHABETS[radix] = alphabet
    return alphabet
