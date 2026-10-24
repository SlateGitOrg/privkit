from __future__ import annotations

import datetime as dt

import pytest

from privkit.pii import validators as v


@pytest.mark.parametrize(
    ("func", "good", "bad"),
    [
        (v.credit_card, ["4111 1111 1111 1111", "378282246310005", "5555-5555-5555-4444", "6011111111111117"],
         ["4111 1111 1111 1112", "1234567812345670", "0000000000000000", "411111111111"]),
        (v.us_ssn, ["123-45-6789", "001-01-0001", "899 99 9999"],
         ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000", "078-05-1120", "12345678"]),
        (v.us_aba_routing, ["021000021", "011000015"], ["021000022", "991000021", "12345"]),
        (v.us_phone, ["(415) 555-0132", "+1 212 867 5309", "2128675309"],
         ["(115) 555-0132", "(415) 155-0132", "(411) 555-0132", "(415) 911-0132", "555-0132", "2222222222"]),
        (v.intl_phone, ["+44 20 7946 0958"], ["+44 12"]),
        (v.in_aadhaar, ["2345 6789 0124"], ["1345 6789 0124", "2345 6789 0125"]),
        (v.uk_nhs, ["943 476 5919"], ["943 476 5918", "000 000 0000"]),
        (v.ipv4, ["10.0.0.1", "255.255.255.255"], ["256.1.1.1", "01.2.3.4"]),
        (v.ipv6, ["fe80::1", "2001:db8:0:0:0:0:2:1"], ["12:30:45", "1::2::3", "ab:cd"]),
        (v.mac_address, ["00:1A:2B:3C:4D:5E", "0011.2233.4455"], ["00:00:00:00:00:00", "00:1A:2B:3C"]),
        (v.date_of_birth, ["1984-03-12", "3/12/1984", "12 March 1984", "March 12, 1984", "1 Sept 1990"],
         ["1984-13-12", "2/30/1984", "12 Smarch 1984", "1850-01-01", "Foo 12, 1984", "12.03.1984"]),
        (v.email, ["a.b@example.com"], ["a..b@example.com", "a.@example.com", "x@localhost"]),
    ],
)  # fmt: skip
def test_validators(func: v.Validator, good: list[str], bad: list[str]) -> None:
    for text in good:
        assert func(text) == len(text), text
    for text in bad:
        assert func(text) is None, text


def test_future_dob_rejected() -> None:
    next_year = dt.date.today().year + 1
    assert v.date_of_birth(f"{next_year}-01-01") is None


def test_iban_trims_trailing_group() -> None:
    text = "DE89 3704 0044 0532 0130 00 BANK"
    assert v.iban(text) == len("DE89 3704 0044 0532 0130 00")
    assert v.iban("XX89 3704 0044 0532 0130 00") is None
    assert v.iban("DE89 3704 0044 0532 0130 01") is None
    assert v.iban("DE89 3704") is None
