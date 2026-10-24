from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from privkit.checksums import (
    aba_check_digit,
    aba_valid,
    iban_check_digits,
    iban_mod97,
    luhn_check_digit,
    luhn_valid,
    nhs_check_digit,
    nhs_valid,
    verhoeff_check_digit,
    verhoeff_valid,
)
from privkit.errors import InvalidInputError


def test_luhn_known_values() -> None:
    assert luhn_valid("79927398713")
    assert not luhn_valid("79927398710")
    assert luhn_valid("4111111111111111")
    assert luhn_check_digit("7992739871") == 3
    assert not luhn_valid("4")
    assert not luhn_valid("41a1")


@given(st.text(alphabet="0123456789", min_size=1, max_size=30))
def test_luhn_generated_check_digit_validates(body: str) -> None:
    assert luhn_valid(body + str(luhn_check_digit(body)))


def test_luhn_detects_single_digit_errors() -> None:
    number = "4111111111111111"
    for i in range(len(number)):
        for d in "0123456789":
            if d != number[i]:
                assert not luhn_valid(number[:i] + d + number[i + 1 :])


def test_iban() -> None:
    assert iban_mod97("DE89370400440532013000") == 1
    assert iban_mod97("GB82WEST12345698765432") == 1
    assert iban_mod97("GB82WEST12345698765433") != 1
    assert iban_check_digits("DE", "370400440532013000") == "89"
    with pytest.raises(InvalidInputError):
        iban_mod97("DE8")


def test_aba() -> None:
    assert aba_valid("011000015")  # Federal Reserve Bank of Boston
    assert aba_valid("021000021")
    assert not aba_valid("021000022")
    assert not aba_valid("12345678")
    assert aba_check_digit("02100002") == 1
    with pytest.raises(InvalidInputError):
        aba_check_digit("123")


def test_verhoeff() -> None:
    assert verhoeff_valid("2363")
    assert not verhoeff_valid("2364")
    assert verhoeff_check_digit("236") == 3
    assert not verhoeff_valid("")


@given(st.text(alphabet="0123456789", min_size=1, max_size=20))
def test_verhoeff_generated(body: str) -> None:
    assert verhoeff_valid(body + str(verhoeff_check_digit(body)))


def test_nhs() -> None:
    assert nhs_valid("9434765919")
    assert not nhs_valid("9434765918")
    assert not nhs_valid("94347659")
    assert nhs_check_digit("943476591") == 9
    with pytest.raises(InvalidInputError):
        nhs_check_digit("12")


def test_nhs_remainder_ten_is_unusable() -> None:
    bodies = [f"{i:09d}" for i in range(100000, 101000)]
    unusable = [b for b in bodies if nhs_check_digit(b) is None]
    assert unusable  # some bodies have no valid check digit
    assert all(not nhs_valid(b + str(d)) for b in unusable[:5] for d in range(10))


def test_digit_guard() -> None:
    with pytest.raises(InvalidInputError):
        luhn_check_digit("12x")
