from __future__ import annotations

import pytest

from privkit.checksums import iban_mod97, luhn_valid, verhoeff_valid
from privkit.evaluation import Span, evaluate, generate_corpus
from privkit.evaluation.corpus import DEV_TEMPLATES, TEST_TEMPLATES
from privkit.evaluation.metrics import EntityScore
from privkit.pii import Detector, Finding


def test_corpus_is_deterministic_and_split_specific() -> None:
    a = generate_corpus("dev", 50, 1)
    assert a == generate_corpus("dev", 50, 1)
    assert a != generate_corpus("dev", 50, 2)
    assert {d.text for d in a}.isdisjoint({d.text for d in generate_corpus("test", 50, 1)})
    assert set(DEV_TEMPLATES).isdisjoint(TEST_TEMPLATES)
    with pytest.raises(ValueError):
        generate_corpus("train", 1, 1)  # type: ignore[arg-type]


def test_labeled_values_are_valid_by_construction() -> None:
    for doc in generate_corpus("test", 300, 3):
        for s in doc.spans:
            value = doc.text[s.start : s.end]
            assert value == value.strip() and value
            digits = "".join(c for c in value if c.isdigit())
            if s.entity == "CREDIT_CARD":
                assert luhn_valid(digits)
            elif s.entity == "IBAN":
                assert iban_mod97(value.replace(" ", "")) == 1
            elif s.entity == "IN_AADHAAR":
                assert verhoeff_valid(digits)


def test_split_name_pools_are_disjoint() -> None:
    dev_people = {
        d.text[s.start : s.end] for d in generate_corpus("dev", 300, 1) for s in d.spans if s.entity == "PERSON"
    }
    test_people = {
        d.text[s.start : s.end] for d in generate_corpus("test", 300, 1) for s in d.spans if s.entity == "PERSON"
    }
    assert dev_people and test_people and dev_people.isdisjoint(test_people)


def test_metrics_math() -> None:
    s = EntityScore(tp=8, fp=2, fn=8)
    assert s.precision == 0.8 and s.recall == 0.5 and s.f1 == pytest.approx(2 * 0.4 / 1.3)
    assert EntityScore().precision == 1.0 and EntityScore().recall == 1.0
    assert EntityScore(fp=1, fn=1).f1 == 0.0


def test_evaluate_strict_matching() -> None:
    from privkit.evaluation.corpus import Document

    doc = Document("d", "x" * 30, (Span("EMAIL", 0, 5), Span("PHONE", 10, 20), Span("PERSON", 22, 25)))

    def predict(text: str) -> list[Finding]:
        return [
            Finding("EMAIL", 0, 5, 1, "r", text[0:5]),  # tp
            Finding("PHONE", 10, 19, 1, "r", text[10:19]),  # boundary off by one -> fp + fn
            Finding("US_SSN", 26, 29, 1, "r", text[26:29]),  # fp
        ]

    report = evaluate([doc], predict, ["EMAIL", "PHONE", "US_SSN"])
    assert report.per_entity["EMAIL"].tp == 1
    assert (report.per_entity["PHONE"].fp, report.per_entity["PHONE"].fn) == (1, 1)
    assert report.per_entity["US_SSN"].fp == 1
    assert "PERSON" not in report.per_entity
    m = report.micro
    assert (m.tp, m.fp, m.fn) == (1, 2, 1)
    assert "**micro**" in report.to_markdown()
    assert report.to_dict()["n_docs"] == 1


def test_detector_scores_high_on_heldout_sample() -> None:
    det = Detector()
    report = evaluate(generate_corpus("test", 200, 99), det.analyze, det.entities)
    assert report.micro.precision > 0.95 and report.micro.recall > 0.95
