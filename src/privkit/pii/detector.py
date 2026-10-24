"""The PII detector: runs recognizers, scores context, resolves overlaps."""

from __future__ import annotations

import bisect
import logging
import re
from collections.abc import Iterable, Sequence
from typing import Protocol

from privkit.errors import ConfigurationError
from privkit.pii.model import Finding
from privkit.pii.recognizers import DEFAULT_RECOGNIZERS, PatternRecognizer

logger = logging.getLogger(__name__)

_WORD = re.compile(r"[A-Za-z][A-Za-z']*")
# A sentence boundary: terminal punctuation followed by whitespace, or a line break.
_BOUNDARY = re.compile(r"[.!?;]\s|\n")
# Another numeric value between a cue word and a candidate "consumes" the cue
# ("SSN: 719-01-7182 Order 768446870" - the cue belongs to the first number).
_VALUE = re.compile(r"\d{3,}")


class SpanRecognizer(Protocol):
    """Anything that proposes findings for a whole text (for example an NER model)."""

    name: str

    def find(self, text: str) -> list[Finding]: ...


class Detector:
    """Detects PII in free text.

    Parameters
    ----------
    recognizers:
        Pattern recognizers to run (defaults to :data:`DEFAULT_RECOGNIZERS`).
    extra:
        Additional span recognizers such as :class:`privkit.pii.ner.SpacyNerRecognizer`.
    threshold:
        Minimum final score for a finding to be reported.
    window_before / window_after:
        Number of words before / after a candidate searched for context words.
    allow_list:
        Exact strings that are never reported (for example a public support address).

    Complexity: O(R * n) regex scanning for R recognizers over n characters,
    plus O(m log m) overlap resolution for m candidates.
    """

    def __init__(
        self,
        recognizers: Sequence[PatternRecognizer] | None = None,
        *,
        extra: Sequence[SpanRecognizer] = (),
        threshold: float = 0.5,
        window_before: int = 6,
        window_after: int = 3,
        allow_list: Iterable[str] = (),
    ) -> None:
        if not 0.0 < threshold <= 1.0:
            raise ConfigurationError("threshold must be in (0, 1]")
        self.recognizers = tuple(DEFAULT_RECOGNIZERS if recognizers is None else recognizers)
        self.extra = tuple(extra)
        self.threshold = threshold
        self.window_before = window_before
        self.window_after = window_after
        self.allow_list = frozenset(allow_list)

    @property
    def entities(self) -> frozenset[str]:
        return frozenset(r.entity.value for r in self.recognizers)

    def _context_words(self, text: str, start: int, end: int, hint: frozenset[str]) -> tuple[frozenset[str], frozenset[str]]:
        """Return (positive-context words, negative-context words) around a candidate.

        Context never crosses a sentence boundary or another numeric value. Negative context (for example
        "version" before a dotted quad) only counts
        when it is one of the two words immediately before the candidate, so a
        cue that belongs to the next value in the sentence does not suppress this one.
        """
        before_text = text[max(0, start - 80) : start]
        for cut in (_BOUNDARY, _VALUE):
            if hits := list(cut.finditer(before_text)):
                before_text = before_text[hits[-1].end() :]
        after_text = text[end : end + 40]
        for cut in (_BOUNDARY, _VALUE):
            if hit := cut.search(after_text):
                after_text = after_text[: hit.start()]
        before = [w.lower().strip("'") for w in _WORD.findall(before_text)]
        after = [w.lower().strip("'") for w in _WORD.findall(after_text)[: self.window_after]]
        positive = frozenset(before[-self.window_before :]) | frozenset(after) | hint
        return positive, frozenset(before[-2:])

    def _candidates(self, text: str, entities: frozenset[str] | None, hint: frozenset[str]) -> list[Finding]:
        found: list[Finding] = []
        for rec in self.recognizers:
            if entities is not None and rec.entity.value not in entities:
                continue
            for match in rec.pattern.finditer(text):
                start, end = match.span()
                evidence = [f"pattern:{rec.name}"]
                if rec.validator is not None:
                    accepted = rec.validator(match.group())
                    if accepted is None:
                        continue
                    end = start + accepted
                    evidence.append("validated")
                score = rec.base_score
                words, near = self._context_words(text, start, end, hint)
                if hits := words & rec.context:
                    score += rec.context_boost
                    evidence.append("context:+" + ",".join(sorted(hits)))
                if misses := near & rec.negative_context:
                    score -= rec.negative_penalty
                    evidence.append("context:-" + ",".join(sorted(misses)))
                score = min(max(score, 0.0), 1.0)
                if score >= self.threshold:
                    found.append(Finding(rec.entity.value, start, end, score, rec.name, text[start:end], tuple(evidence)))
        for span_rec in self.extra:
            for f in span_rec.find(text):
                if (entities is None or f.entity in entities) and f.score >= self.threshold:
                    found.append(f)
        return found

    def analyze(
        self,
        text: str,
        *,
        entities: Iterable[str] | None = None,
        context_hint: Iterable[str] = (),
    ) -> list[Finding]:
        """Return non-overlapping findings sorted by position.

        ``context_hint`` adds words treated as if they surrounded every
        candidate; the structured scanner passes column-header words this way.
        """
        wanted = frozenset(entities) if entities is not None else None
        hint = frozenset(w.lower() for w in context_hint)
        candidates = [c for c in self._candidates(text, wanted, hint) if c.text not in self.allow_list]
        kept = resolve_overlaps(candidates)
        logger.debug("analyzed %d chars: %d candidates, %d findings", len(text), len(candidates), len(kept))
        return kept


def resolve_overlaps(candidates: Sequence[Finding]) -> list[Finding]:
    """Greedy interval selection: prefer higher score, then longer span, then earlier start.

    Uses a sorted list of kept intervals with binary search, O(m log m) overall
    for m candidates (insertion into a Python list is a memmove, fast in practice).
    """
    order = sorted(candidates, key=lambda f: (-f.score, -f.length, f.start))
    starts: list[int] = []
    kept: list[Finding] = []
    for cand in order:
        i = bisect.bisect_left(starts, cand.start)
        if i > 0 and kept[i - 1].end > cand.start:
            continue
        if i < len(kept) and kept[i].start < cand.end:
            continue
        starts.insert(i, cand.start)
        kept.insert(i, cand)
    return kept
