"""Runs only when the optional spaCy extra and en_core_web_sm are installed (``make ner-model``)."""

from __future__ import annotations

import pytest

from privkit.pii import Detector, SpacyNerRecognizer, ner_available

pytestmark = pytest.mark.skipif(not ner_available(), reason="spaCy model en_core_web_sm not installed")


def test_spacy_ner_finds_person_and_location() -> None:
    det = Detector(extra=[SpacyNerRecognizer()])
    found = det.analyze("Please ask Maria Gonzalez in Denver to email maria.g@example.com.")
    entities = {(f.entity, f.text) for f in found}
    assert ("PERSON", "Maria Gonzalez") in entities
    assert ("LOCATION", "Denver") in entities
    assert ("EMAIL", "maria.g@example.com") in entities
