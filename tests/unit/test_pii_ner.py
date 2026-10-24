from __future__ import annotations

from dataclasses import dataclass

import pytest

from privkit.errors import OptionalDependencyError
from privkit.pii import Detector, SpacyNerRecognizer, ner_available
from privkit.pii import ner as ner_mod


@dataclass
class FakeSpan:
    text: str
    label_: str
    start_char: int
    end_char: int


class FakeDoc:
    def __init__(self, ents: list[FakeSpan]) -> None:
        self.ents = ents


class FakeNlp:
    """Mimics a spaCy pipeline: tags capitalized two-word names as PERSON and 'Denver' as GPE."""

    def __call__(self, text: str) -> FakeDoc:
        ents = []
        i = text.find("Maria Gonzalez")
        if i >= 0:
            ents.append(FakeSpan("Maria Gonzalez", "PERSON", i, i + 14))
        j = text.find("Denver")
        if j >= 0:
            ents.append(FakeSpan("Denver", "GPE", j, j + 6))
        k = text.find("Acme")
        if k >= 0:
            ents.append(FakeSpan("Acme", "ORG", k, k + 4))  # unmapped label -> ignored
        return FakeDoc(ents)


def test_ner_adapter_maps_labels() -> None:
    rec = SpacyNerRecognizer(FakeNlp())
    det = Detector(extra=[rec])
    found = det.analyze("Maria Gonzalez of Acme moved to Denver; mail maria@example.com")
    assert [(f.entity, f.text) for f in found] == [
        ("PERSON", "Maria Gonzalez"),
        ("LOCATION", "Denver"),
        ("EMAIL", "maria@example.com"),
    ]
    assert found[0].evidence == ("ner:PERSON",)
    assert det.analyze("Maria Gonzalez", entities=["EMAIL"]) == []


def test_missing_spacy_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_import(name: str) -> object:
        raise ImportError(name)

    monkeypatch.setattr("privkit.pii.ner.importlib.import_module", fake_import)
    with pytest.raises(OptionalDependencyError):
        SpacyNerRecognizer()
    assert ner_available() is False


def test_missing_model_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSpacy:
        @staticmethod
        def load(name: str, disable: list[str]) -> object:
            raise OSError(name)

    monkeypatch.setattr("privkit.pii.ner.importlib.import_module", lambda name: FakeSpacy)
    with pytest.raises(OptionalDependencyError):
        ner_mod.load_spacy_model("nope")


def test_loads_model_via_spacy(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSpacy:
        @staticmethod
        def load(name: str, disable: list[str]) -> object:
            return FakeNlp()

    monkeypatch.setattr("privkit.pii.ner.importlib.import_module", lambda name: FakeSpacy)
    assert ner_available("whatever")
    assert SpacyNerRecognizer(model="whatever").find("Denver")[0].entity == "LOCATION"
