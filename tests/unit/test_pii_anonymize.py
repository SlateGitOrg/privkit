from __future__ import annotations

import logging

import pytest

from privkit.errors import ConfigurationError, DomainTooSmallError, InvalidInputError
from privkit.pii import Detector, Finding, Mask, Pseudonymize, Redact, Tokenize, anonymize, detokenize_text
from privkit.tokens import Tokenizer

TEXT = "Card 4111 1111 1111 1111, mail ann.lee@example.com, ssn 123-45-6789."
KEY = bytes(range(32))


@pytest.fixture(scope="module")
def findings() -> list[Finding]:
    return Detector().analyze(TEXT)


def test_default_redact(findings: list[Finding]) -> None:
    out = anonymize(TEXT, findings)
    assert out.text == "Card <CREDIT_CARD>, mail <EMAIL>, ssn <US_SSN>."
    for r in out.replacements:
        assert out.text[r.start : r.end] == f"<{r.entity}>" and r.operator == "Redact"


def test_mask_and_custom_template(findings: list[Finding]) -> None:
    out = anonymize(TEXT, findings, {"CREDIT_CARD": Mask()}, default=Redact("[{entity}]"))
    assert out.text == "Card **** **** **** 1111, mail [EMAIL], ssn [US_SSN]."
    assert Mask(keep_last=0, keep_separators=False).apply(findings[2]) == "*" * 11
    with pytest.raises(ConfigurationError):
        Mask(char="ab")


def test_pseudonymize_is_stable_and_keyed(findings: list[Finding]) -> None:
    p1, p2 = Pseudonymize(KEY), Pseudonymize(bytes(32))
    a = p1.apply(findings[1])
    assert a == p1.apply(findings[1]) and a.startswith("EMAIL_") and len(a) == len("EMAIL_") + 12
    assert a != p2.apply(findings[1])
    with pytest.raises(ConfigurationError):
        Pseudonymize(b"short")


def test_tagged_tokenize_roundtrip(findings: list[Finding]) -> None:
    tok = Tokenizer(KEY)
    out = anonymize(TEXT, findings, default=Tokenize(tok, tagged=True))
    assert "4111 1111 1111 1111" not in out.text and "[[CREDIT_CARD:" in out.text
    assert detokenize_text(out.text, tok) == TEXT


def test_untagged_tokenize_preserves_format(findings: list[Finding]) -> None:
    tok = Tokenizer(KEY)
    out = anonymize(TEXT, findings, default=Tokenize(tok))
    assert out.text.startswith("Card ") and out.text.count("@example.com") == 1
    assert len(out.text) == len(TEXT)


def test_tokenize_error_fallback(caplog: pytest.LogCaptureFixture) -> None:
    tok = Tokenizer(KEY)
    tiny = Finding("EMAIL", 0, 8, 0.9, "email", "ab@x.org")
    caplog.set_level(logging.WARNING)
    assert Tokenize(tok).apply(tiny) == "<EMAIL>"
    assert "ab@x.org" not in caplog.text
    with pytest.raises(DomainTooSmallError):
        Tokenize(tok, on_error="raise").apply(tiny)


def test_anonymize_rejects_bad_findings() -> None:
    a = Finding("X", 0, 4, 0.9, "r", "abcd")
    b = Finding("Y", 2, 6, 0.9, "r", "cdef")
    with pytest.raises(InvalidInputError):
        anonymize("abcdefgh", [a, b])
    with pytest.raises(InvalidInputError):
        anonymize("zzzzzzzz", [a])
    assert anonymize("abcdefgh", []).text == "abcdefgh"
