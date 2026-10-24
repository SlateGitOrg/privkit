from __future__ import annotations

import logging

import pytest

from privkit.errors import ConfigurationError
from privkit.pii import DEFAULT_RECOGNIZERS, Detector, Entity, Finding, resolve_overlaps


@pytest.fixture(scope="module")
def det() -> Detector:
    return Detector()


def _ents(det: Detector, text: str) -> list[tuple[str, str]]:
    return [(f.entity, f.text) for f in det.analyze(text)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail jane.doe@example.com now", ("EMAIL", "jane.doe@example.com")),
        ("card 4111-1111-1111-1111.", ("CREDIT_CARD", "4111-1111-1111-1111")),
        ("ssn 123-45-6789", ("US_SSN", "123-45-6789")),
        ("call (212) 867-5309", ("PHONE", "(212) 867-5309")),
        ("dial +44 20 7946 0958", ("PHONE", "+44 20 7946 0958")),
        ("IBAN: GB82 WEST 1234 5698 7654 32", ("IBAN", "GB82 WEST 1234 5698 7654 32")),
        ("from 192.168.0.17", ("IP_ADDRESS", "192.168.0.17")),
        ("host 2001:db8::8a2e:370:7334 up", ("IP_ADDRESS", "2001:db8::8a2e:370:7334")),
        ("mac 00-1A-2B-3C-4D-5E", ("MAC_ADDRESS", "00-1A-2B-3C-4D-5E")),
        ("routing number 021000021", ("US_ABA_ROUTING", "021000021")),
        ("aadhaar 2345 6789 0124", ("IN_AADHAAR", "2345 6789 0124")),
        ("NHS number 943 476 5919", ("UK_NHS", "943 476 5919")),
        ("born on 12 March 1984", ("DATE_OF_BIRTH", "12 March 1984")),
    ],
)
def test_detects_each_entity(det: Detector, text: str, expected: tuple[str, str]) -> None:
    assert _ents(det, text) == [expected]


@pytest.mark.parametrize(
    "text",
    [
        "order 4111 1111 1111 1112 shipped",  # Luhn-invalid
        "reference 123456789",  # bare 9 digits without context
        "SSN 000-12-3456",  # impossible SSN
        "upgrade to version 2.10.4.1",  # version string
        "meeting at 10:30:15",  # time, not IPv6
        "the meeting is on 2024-05-03",  # date without birth context
        "IBAN DE00 3704 0044 0532 0130 00",  # bad IBAN check digits
        "call 911 now",
        "Ref DE36 9563 0320 9872 5428 89",  # card-shaped digits inside an IBAN-like token
    ],
)
def test_hard_negatives(det: Detector, text: str) -> None:
    assert det.analyze(text) == []


def test_context_boost_and_evidence(det: Detector) -> None:
    [f] = det.analyze("Her social security number is 123456789.")
    assert f.entity == "US_SSN" and any(e.startswith("context:+") for e in f.evidence)
    assert f.score == pytest.approx(0.65)


def test_context_does_not_cross_sentences_or_values(det: Detector) -> None:
    assert det.analyze("Order 761670153 shipped. SSN on file.") == []
    found = det.analyze("SSN: 719-01-7182 Order 768446870 shipped")
    assert [f.text for f in found] == ["719-01-7182"]


def test_negative_context_only_immediately_before(det: Detector) -> None:
    assert _ents(det, "Server 10.0.12.7 runs version 2.10.4.1.") == [("IP_ADDRESS", "10.0.12.7")]


def test_entity_filter_allow_list_and_hint() -> None:
    det = Detector(allow_list={"support@example.com"})
    text = "write support@example.com or ann@example.com, card 4111111111111111"
    assert [f.text for f in det.analyze(text)] == ["ann@example.com", "4111111111111111"]
    assert [f.entity for f in det.analyze(text, entities=["CREDIT_CARD"])] == ["CREDIT_CARD"]
    assert det.analyze("123456789") == []
    assert [f.entity for f in det.analyze("123456789", context_hint=["SSN"])] == ["US_SSN"]


def test_threshold_validation_and_custom_threshold() -> None:
    with pytest.raises(ConfigurationError):
        Detector(threshold=0)
    strict = Detector(threshold=0.95)
    assert strict.analyze("call (212) 867-5309") == []
    assert "EMAIL" in strict.entities


def test_custom_recognizer_subset() -> None:
    only_email = Detector([r for r in DEFAULT_RECOGNIZERS if r.entity is Entity.EMAIL])
    assert [f.entity for f in only_email.analyze("a@example.com 4111111111111111")] == ["EMAIL"]


def test_overlap_resolution_prefers_score_then_length() -> None:
    a = Finding("A", 0, 10, 0.9, "r", "x" * 10)
    b = Finding("B", 5, 15, 0.8, "r", "x" * 10)
    c = Finding("C", 10, 12, 0.5, "r", "xx")
    d = Finding("D", 0, 12, 0.9, "r", "x" * 12)
    assert [f.entity for f in resolve_overlaps([a, b, c])] == ["A", "C"]
    assert [f.entity for f in resolve_overlaps([a, d])] == ["D"]
    assert resolve_overlaps([]) == []


def test_finding_repr_hides_value_and_logs_are_clean(det: Detector, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="privkit")
    [f] = det.analyze("ssn 123-45-6789")
    assert "123-45-6789" not in repr(f)
    assert "123-45-6789" not in caplog.text
    assert f.to_dict()["entity"] == "US_SSN" and "text" not in f.to_dict()
    assert f.to_dict(include_text=True)["text"] == "123-45-6789"
    assert f.length == 11


def test_multiline_and_punctuation(det: Detector) -> None:
    text = 'Contact: "ann@example.com"\nPhone: <212-867-5309>\nSSN: 123-45-6789'
    assert [f.entity for f in det.analyze(text)] == ["EMAIL", "PHONE", "US_SSN"]
