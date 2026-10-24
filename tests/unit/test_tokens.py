from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from privkit.checksums import luhn_check_digit, luhn_valid
from privkit.errors import ConfigurationError, DomainTooSmallError, InvalidInputError, KeyMaterialError
from privkit.fpe import ALNUM, DIGITS, Algorithm
from privkit.tokens import DEFAULT_POLICIES, Codec, LuhnMode, Normalize, Tokenizer, TokenPolicy

KEY = bytes(range(32))


@pytest.fixture
def tok() -> Tokenizer:
    return Tokenizer(KEY)


@pytest.mark.parametrize(
    ("value", "policy"),
    [
        ("4111 1111 1111 1111", "CREDIT_CARD"),
        ("378282246310005", "CREDIT_CARD"),
        ("123-45-6789", "US_SSN"),
        ("(415) 555-0132", "PHONE"),
        ("jane.doe+news@example.co.uk", "EMAIL"),
        ("DE89 3704 0044 0532 0130 00", "IBAN"),
        ("10.0.0.7", "IP_ADDRESS"),
        ("fe80::1ff:fe23:4567:890a", "IP_ADDRESS"),
        ("Maria Gonzalez", "PERSON"),
        ("1984-03-12", "DATE_OF_BIRTH"),
    ],
)
def test_roundtrip_default_policies(tok: Tokenizer, value: str, policy: str) -> None:
    token = tok.tokenize(value, policy)
    assert token != value
    assert len(token) == len(value) or policy == "IP_ADDRESS"
    assert tok.detokenize(token, policy) == value


def test_format_is_preserved(tok: Tokenizer) -> None:
    token = tok.tokenize("4111-1111-1111-1234", "CREDIT_CARD")
    assert token[4] == "-" and token[9] == "-" and token.endswith("1234")
    email = tok.tokenize("jane.doe@example.com", "EMAIL")
    assert email.endswith("@example.com") and email[4] == "."
    ip = tok.tokenize("192.168.1.1", "IP_ADDRESS")
    ipaddress.IPv4Address(ip)  # still a valid address


def test_determinism_and_key_separation() -> None:
    a, b = Tokenizer(KEY), Tokenizer(bytes(32))
    assert a.tokenize("123-45-6789", "US_SSN") == a.tokenize("123-45-6789", "US_SSN")
    assert a.tokenize("123-45-6789", "US_SSN") != b.tokenize("123-45-6789", "US_SSN")
    # Same digits under different policies use different derived keys.
    assert a.tokenize("123456789", "US_SSN") != a.tokenize("123456789", "US_ABA_ROUTING")


def test_kept_suffix_is_bound_into_tweak(tok: Tokenizer) -> None:
    # same middle digits, different last four -> different middle tokens
    t1 = tok.tokenize("411111111111" + "1111", "CREDIT_CARD")
    t2 = tok.tokenize("411111111111" + "2222", "CREDIT_CARD")
    assert t1[:12] != t2[:12]


@pytest.mark.parametrize("algorithm", [Algorithm.FF1, Algorithm.FF3_1])
def test_luhn_modes(tok: Tokenizer, algorithm: Algorithm) -> None:
    valid = TokenPolicy("PAN_VALID", luhn=LuhnMode.VALID, algorithm=algorithm)
    invalid = TokenPolicy("PAN_INVALID", luhn=LuhnMode.INVALID, algorithm=algorithm)
    for pan in ["4111111111111111", "5500005555555559", "378282246310005"]:
        tv = tok.tokenize(pan, valid)
        ti = tok.tokenize(pan, invalid)
        assert luhn_valid(tv) and not luhn_valid(ti)
        assert tok.detokenize(tv, valid) == pan
        assert tok.detokenize(ti, invalid) == pan


def test_luhn_rejects_invalid_input(tok: Tokenizer) -> None:
    with pytest.raises(InvalidInputError):
        tok.tokenize("4111111111111112", TokenPolicy("P", luhn=LuhnMode.VALID))
    with pytest.raises(InvalidInputError):
        tok.tokenize("1", TokenPolicy("P", luhn=LuhnMode.VALID))


@settings(max_examples=50, deadline=None)
@given(body=st.text(alphabet="0123456789", min_size=12, max_size=18))
def test_luhn_valid_property(body: str) -> None:
    pan = body + str(luhn_check_digit(body))
    t = Tokenizer(KEY)
    pol = TokenPolicy("PAN", luhn=LuhnMode.VALID)
    token = t.tokenize(pan, pol)
    assert luhn_valid(token) and t.detokenize(token, pol) == pan


def test_domain_too_small(tok: Tokenizer) -> None:
    with pytest.raises(DomainTooSmallError):
        tok.tokenize("1234", "US_SSN")
    with pytest.raises(DomainTooSmallError):
        tok.tokenize("ab@x.io", "EMAIL")  # 62^2 values
    with pytest.raises(DomainTooSmallError):
        tok.tokenize("1234", "CREDIT_CARD")  # all kept
    with pytest.raises(DomainTooSmallError):
        tok.tokenize("10.1.2.3", TokenPolicy("NET", codec=Codec.IP, keep_prefix=2))


def test_ip_keep_prefix(tok: Tokenizer) -> None:
    pol = TokenPolicy("NET8", codec=Codec.IP, keep_prefix=1)
    out = tok.tokenize("10.20.30.40", pol)
    assert out.startswith("10.") and tok.detokenize(out, pol) == "10.20.30.40"
    with pytest.raises(InvalidInputError):
        tok.tokenize("not-an-ip", "IP_ADDRESS")


def test_normalization_and_span(tok: Tokenizer) -> None:
    mac = tok.tokenize("00:1A:2B:3C:4D:5E", "MAC_ADDRESS")
    assert tok.detokenize(mac, "MAC_ADDRESS") == "00:1a:2b:3c:4d:5e"
    with pytest.raises(InvalidInputError):
        tok.tokenize("no-at-sign", "EMAIL")
    upper = TokenPolicy("U", ALNUM, normalize=Normalize.UPPER)
    assert tok.detokenize(tok.tokenize("abcdef", upper), upper) == "ABCDEF"


def test_too_long_for_ff3_1(tok: Tokenizer) -> None:
    pol = TokenPolicy("LONG", DIGITS, algorithm=Algorithm.FF3_1)
    with pytest.raises(InvalidInputError):
        tok.tokenize("1" * 60, pol)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": ""},
        {"name": "x", "keep_prefix": -1},
        {"name": "x", "luhn": LuhnMode.VALID, "alphabet": ALNUM},
        {"name": "x", "luhn": LuhnMode.VALID, "keep_suffix": 4},
        {"name": "x", "codec": Codec.IP, "keep_suffix": 1},
        {"name": "x", "span_pattern": "no-group"},
    ],
)
def test_policy_validation(kwargs: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError):
        TokenPolicy(**kwargs)  # type: ignore[arg-type]


def test_unknown_policy_and_bad_key() -> None:
    with pytest.raises(ConfigurationError):
        Tokenizer(KEY).tokenize("x", "NOPE")
    with pytest.raises(KeyMaterialError):
        Tokenizer(b"short")


def test_custom_policy_mapping() -> None:
    t = Tokenizer(KEY, policies={"ACCT": TokenPolicy("ACCT", DIGITS, keep_prefix=2)})
    out = t.tokenize("99-1234567", "ACCT")
    assert out.startswith("99-") and t.detokenize(out, "ACCT") == "99-1234567"
    assert set(DEFAULT_POLICIES) >= {"CREDIT_CARD", "EMAIL", "IP_ADDRESS"}
