"""FF1 / FF3-1 against NIST vectors.

* SP 800-38G "FF1 samples" (the nine classic examples published by NIST CSRC).
* ACVP-Server ``internalProjection.json`` for ACVP-AES-FF1-1.0 (750 cases) and
  ACVP-AES-FF3-1-1.0 (450 cases), covering every key size, several radixes and
  both directions. Source and checksums are recorded in DATA.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from privkit.fpe import FF1, FF3_1, Alphabet

VECTORS = Path(__file__).resolve().parent.parent / "vectors"

K128 = "2B7E151628AED2A6ABF7158809CF4F3C"
K192 = K128 + "EF4359D8D580AA4F"
K256 = K192 + "7F036D6F04FC6A94"
RADIX10 = "0123456789"
RADIX36 = "0123456789abcdefghijklmnopqrstuvwxyz"

NIST_FF1_SAMPLES = [
    (1, K128, RADIX10, "", "0123456789", "2433477484"),
    (2, K128, RADIX10, "39383736353433323130", "0123456789", "6124200773"),
    (3, K128, RADIX36, "3737373770717273373737", "0123456789abcdefghi", "a9tv40mll9kdu509eum"),
    (4, K192, RADIX10, "", "0123456789", "2830668132"),
    (5, K192, RADIX10, "39383736353433323130", "0123456789", "2496655549"),
    (6, K192, RADIX36, "3737373770717273373737", "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"),
    (7, K256, RADIX10, "", "0123456789", "6657667009"),
    (8, K256, RADIX10, "39383736353433323130", "0123456789", "1001623463"),
    (9, K256, RADIX36, "3737373770717273373737", "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"),
]


@pytest.mark.parametrize(("sample", "key", "chars", "tweak", "pt", "ct"), NIST_FF1_SAMPLES)
def test_ff1_nist_samples(sample: int, key: str, chars: str, tweak: str, pt: str, ct: str) -> None:
    alphabet = Alphabet(chars)
    ff1 = FF1(bytes.fromhex(key), alphabet.radix)
    t = bytes.fromhex(tweak)
    assert alphabet.from_numerals(ff1.encrypt_numerals(alphabet.to_numerals(pt), t)) == ct
    assert alphabet.from_numerals(ff1.decrypt_numerals(alphabet.to_numerals(ct), t)) == pt


def _acvp_cases(filename: str) -> list[Any]:
    data = json.loads((VECTORS / filename).read_text())
    cases = []
    for group in data["testGroups"]:
        for test in group["tests"]:
            cases.append(
                pytest.param(group["direction"], group["alphabet"], test, id=f"tg{group['tgId']}-tc{test['tcId']}")
            )
    return cases


def _run(cipher: FF1 | FF3_1, direction: str, alphabet: Alphabet, test: dict[str, str]) -> None:
    tweak = bytes.fromhex(test["tweak"])
    if direction == "encrypt":
        got = cipher.encrypt_numerals(alphabet.to_numerals(test["pt"]), tweak)
        assert alphabet.from_numerals(got) == test["ct"]
    else:
        got = cipher.decrypt_numerals(alphabet.to_numerals(test["ct"]), tweak)
        assert alphabet.from_numerals(got) == test["pt"]


@pytest.mark.parametrize(("direction", "chars", "test"), _acvp_cases("acvp-aes-ff1-internalProjection.json"))
def test_ff1_acvp(direction: str, chars: str, test: dict[str, str]) -> None:
    alphabet = Alphabet(chars)
    _run(FF1(bytes.fromhex(test["key"]), alphabet.radix), direction, alphabet, test)


@pytest.mark.parametrize(("direction", "chars", "test"), _acvp_cases("acvp-aes-ff3-1-internalProjection.json"))
def test_ff3_1_acvp(direction: str, chars: str, test: dict[str, str]) -> None:
    alphabet = Alphabet(chars)
    _run(FF3_1(bytes.fromhex(test["key"]), alphabet.radix), direction, alphabet, test)


def test_vector_counts() -> None:
    ff1 = json.loads((VECTORS / "acvp-aes-ff1-internalProjection.json").read_text())
    ff3 = json.loads((VECTORS / "acvp-aes-ff3-1-internalProjection.json").read_text())
    assert sum(len(g["tests"]) for g in ff1["testGroups"]) == 750
    assert sum(len(g["tests"]) for g in ff3["testGroups"]) == 450
