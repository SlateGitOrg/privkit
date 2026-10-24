"""Optional named-entity recognition via spaCy.

spaCy is an optional extra (``uv sync --extra ner`` plus ``make ner-model``).
The adapter accepts any object that behaves like a spaCy ``Language`` (callable
returning a doc with ``.ents``), which keeps the integration testable without
the model being installed.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from privkit.errors import OptionalDependencyError
from privkit.pii.model import Entity, Finding

DEFAULT_LABEL_MAP: Mapping[str, Entity] = {
    "PERSON": Entity.PERSON,
    "PER": Entity.PERSON,
    "GPE": Entity.LOCATION,
    "LOC": Entity.LOCATION,
}


class _Span(Protocol):
    text: str
    label_: str
    start_char: int
    end_char: int


class _Doc(Protocol):
    @property
    def ents(self) -> Iterable[_Span]: ...


class SpacyNerRecognizer:
    """Wraps a spaCy pipeline; spaCy NER exposes no calibrated confidences, so a fixed score is used."""

    name = "spacy_ner"

    def __init__(
        self,
        nlp: Any = None,
        *,
        model: str = "en_core_web_sm",
        score: float = 0.7,
        label_map: Mapping[str, Entity] = DEFAULT_LABEL_MAP,
    ) -> None:
        if nlp is None:
            nlp = load_spacy_model(model)
        self._nlp = nlp
        self.score = score
        self.label_map = dict(label_map)

    def find(self, text: str) -> list[Finding]:
        doc: _Doc = self._nlp(text)
        out = []
        for ent in doc.ents:
            entity = self.label_map.get(ent.label_)
            if entity is None:
                continue
            out.append(
                Finding(
                    entity.value,
                    ent.start_char,
                    ent.end_char,
                    self.score,
                    self.name,
                    text[ent.start_char : ent.end_char],
                    (f"ner:{ent.label_}",),
                )
            )
        return out


def load_spacy_model(model: str) -> Any:
    """Import spaCy and load ``model``; raises :class:`OptionalDependencyError` if unavailable."""
    try:
        spacy = importlib.import_module("spacy")
    except ImportError as exc:
        raise OptionalDependencyError("spaCy is not installed; run `uv sync --extra ner`") from exc
    try:
        return spacy.load(model, disable=["lemmatizer", "tagger", "parser", "attribute_ruler"])
    except OSError as exc:
        raise OptionalDependencyError(f"spaCy model {model!r} is not installed; run `make ner-model`") from exc


def ner_available(model: str = "en_core_web_sm") -> bool:
    try:
        load_spacy_model(model)
    except OptionalDependencyError:
        return False
    return True
