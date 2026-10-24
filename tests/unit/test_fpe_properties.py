"""Property-based and edge-case tests for the FPE layer."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from privkit.errors import InvalidInputError, KeyMaterialError
from privkit.fpe import (
    ALNUM,
    DIGITS,
    FF1,
    FF3_1,
    Algorithm,
    Alphabet,
    FormatPreservingCipher,
    alphabet_by_name,
)
from privkit.fpe._numeral import min_length, num_radix, str_radix
from privkit.fpe.ff3_1 import ff3_1_maxlen

keys = st.sampled_from([16, 24, 32]).flatmap(lambda n: st.binary(min_size=n, max_size=n))


@settings(max_examples=60, deadline=None)
@given(key=keys, digits=st.text(alphabet="0123456789", min_size=6, max_size=40), tweak=st.binary(max_size=40))
def test_ff1_roundtrip_digits(key: bytes, digits: str, tweak: bytes) -> None:
    c = FormatPreservingCipher(key, DIGITS)
    token = c.encrypt(digits, tweak)
    assert len(token) == len(digits) and token.isdigit()
    assert c.decrypt(token, tweak) == digits


@settings(max_examples=60, deadline=None)
@given(key=keys, text=st.text(alphabet=ALNUM.chars, min_size=4, max_size=32), tweak=st.binary(min_size=7, max_size=7))
def test_ff3_1_roundtrip_alnum(key: bytes, text: str, tweak: bytes) -> None:
    c = FormatPreservingCipher(key, ALNUM, Algorithm.FF3_1)
    token = c.encrypt(text, tweak)
    assert len(token) == len(text) and all(ch in ALNUM for ch in token)
    assert c.decrypt(token, tweak) == text


@settings(max_examples=40, deadline=None)
@given(radix=st.integers(2, 300), data=st.data())
def test_ff1_is_permutation_like_on_random_radix(radix: int, data: st.DataObject) -> None:
    ff1 = FF1(bytes(16), radix)
    n = data.draw(st.integers(ff1.minlen, ff1.minlen + 6))
    numerals = data.draw(st.lists(st.integers(0, radix - 1), min_size=n, max_size=n))
    out = ff1.encrypt_numerals(numerals, b"t")
    assert all(0 <= d < radix for d in out)
    assert ff1.decrypt_numerals(out, b"t") == numerals


def test_ff1_is_a_bijection_on_small_domain() -> None:
    # radix 2, n=20 -> 2^20 >= 10^6. Check injectivity on a slice of the domain.
    ff1 = FF1(bytes(range(16)), 2)
    outs = {tuple(ff1.encrypt_numerals(str_radix(x, 2, 20))) for x in range(5000)}
    assert len(outs) == 5000


def test_tweak_changes_ciphertext() -> None:
    c = FormatPreservingCipher(bytes(32), DIGITS)
    assert c.encrypt("1234567890", b"a") != c.encrypt("1234567890", b"b")


def test_numeral_helpers() -> None:
    assert num_radix([1, 2, 3], 10) == 123
    assert str_radix(123, 10, 5) == [0, 0, 1, 2, 3]
    with pytest.raises(InvalidInputError):
        str_radix(1000, 10, 2)
    assert min_length(10) == 6
    assert min_length(2) == 20
    assert min_length(1 << 16) == 2
    assert ff3_1_maxlen(10) == 56
    assert ff3_1_maxlen(2) == 192


@pytest.mark.parametrize(
    "bad",
    [
        lambda: FF1(bytes(16), 1),
        lambda: FF1(bytes(16), (1 << 16) + 1),
        lambda: FF1(bytes(16), 10, max_tweak_len=-1),
        lambda: FF1(bytes(16), 10).encrypt_numerals([1, 2, 3]),  # below minlen
        lambda: FF1(bytes(16), 10).encrypt_numerals([1, 2, 3, 4, 5, 10]),  # numeral >= radix
        lambda: FF1(bytes(16), 10, max_tweak_len=2).encrypt_numerals([1] * 6, b"abc"),
        lambda: FF3_1(bytes(16), 10).encrypt_numerals([1] * 6, b"short"),
        lambda: FF3_1(bytes(16), 10).encrypt_numerals([1] * 57, bytes(7)),  # above maxlen
        lambda: FF3_1(bytes(16), 1),
        lambda: FormatPreservingCipher(bytes(16), DIGITS, Algorithm.FF3_1).encrypt("123456", b"x"),
        lambda: DIGITS.to_numerals("12a"),
        lambda: Alphabet("a"),
        lambda: Alphabet("aa"),
        lambda: alphabet_by_name("klingon"),
    ],
)
def test_invalid_inputs_raise(bad: object) -> None:
    with pytest.raises(InvalidInputError):
        bad()  # type: ignore[operator]


def test_bad_key_lengths() -> None:
    with pytest.raises(KeyMaterialError):
        FF1(bytes(15), 10)
    with pytest.raises(KeyMaterialError):
        FF3_1(bytes(33), 10)


def test_alphabet_contains_and_named() -> None:
    assert "7" in DIGITS and "a" not in DIGITS and 7 not in DIGITS
    assert alphabet_by_name("hex").radix == 16
    huge = Alphabet("".join(chr(0x10000 + i) for i in range(1 << 16)))
    assert huge.radix == 1 << 16
    with pytest.raises(InvalidInputError):
        Alphabet("".join(chr(0x10000 + i) for i in range((1 << 16) + 1)))


def test_cipher_defaults_and_properties() -> None:
    c = FormatPreservingCipher(bytes(16), DIGITS, Algorithm.FF3_1)
    assert c.minlen == 6 and c.maxlen == 56
    token = c.encrypt("000000")  # default all-zero tweak
    assert c.decrypt(token) == "000000"
