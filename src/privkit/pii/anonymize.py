"""Anonymization operators applied to detected findings.

Operators turn each finding into replacement text:

* :class:`Redact` - fixed placeholder such as ``<EMAIL>`` (irreversible).
* :class:`Mask` - replace characters with ``*`` keeping the last few (irreversible).
* :class:`Pseudonymize` - keyed HMAC-SHA256 digest, stable per value (irreversible,
  linkable across documents under the same key).
* :class:`Tokenize` - FF1/FF3-1 format-preserving token (reversible with the key).
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol

from privkit.errors import ConfigurationError, InvalidInputError, PrivkitError
from privkit.pii.model import Finding
from privkit.tokens import Tokenizer

logger = logging.getLogger(__name__)

TAG_PATTERN = re.compile(r"\[\[([A-Z][A-Z0-9_]*):((?:(?!\]\]).)+)\]\]")


class Operator(Protocol):
    def apply(self, finding: Finding) -> str: ...


@dataclass(frozen=True)
class Redact:
    template: str = "<{entity}>"

    def apply(self, finding: Finding) -> str:
        return self.template.format(entity=finding.entity)


@dataclass(frozen=True)
class Mask:
    char: str = "*"
    keep_last: int = 4
    keep_separators: bool = True

    def __post_init__(self) -> None:
        if len(self.char) != 1 or self.keep_last < 0:
            raise ConfigurationError("mask char must be one character and keep_last >= 0")

    def apply(self, finding: Finding) -> str:
        text = finding.text
        alnum_positions = [i for i, c in enumerate(text) if c.isalnum()]
        keep = set(alnum_positions[len(alnum_positions) - self.keep_last :]) if self.keep_last else set()
        out = []
        for i, c in enumerate(text):
            if i in keep or (self.keep_separators and not c.isalnum()):
                out.append(c)
            else:
                out.append(self.char)
        return "".join(out)


@dataclass(frozen=True)
class Pseudonymize:
    key: bytes = field(repr=False)
    length: int = 12

    def __post_init__(self) -> None:
        if len(self.key) < 16 or not 4 <= self.length <= 64:
            raise ConfigurationError("pseudonym key must be >= 16 bytes and length in [4, 64]")

    def apply(self, finding: Finding) -> str:
        mac = hmac.new(self.key, f"{finding.entity}\x00{finding.text}".encode(), hashlib.sha256)
        return f"{finding.entity}_{mac.hexdigest()[: self.length]}"


@dataclass(frozen=True)
class Tokenize:
    """Reversible FPE token. ``tagged`` wraps it as ``[[ENTITY:token]]`` so free text can be detokenized."""

    tokenizer: Tokenizer
    tagged: bool = False
    on_error: Literal["redact", "raise"] = "redact"

    def apply(self, finding: Finding) -> str:
        try:
            token = self.tokenizer.tokenize(finding.text, finding.entity)
        except PrivkitError as exc:
            if self.on_error == "raise":
                raise
            logger.warning(
                "tokenization of a %s finding failed (%s); redacting instead", finding.entity, type(exc).__name__
            )
            return f"<{finding.entity}>"
        return f"[[{finding.entity}:{token}]]" if self.tagged else token


@dataclass(frozen=True)
class Replacement:
    entity: str
    start: int  # offsets in the anonymized text
    end: int
    operator: str


@dataclass(frozen=True)
class AnonymizedText:
    text: str
    replacements: tuple[Replacement, ...]


def anonymize(
    text: str,
    findings: Sequence[Finding],
    operators: Mapping[str, Operator] | None = None,
    default: Operator | None = None,
) -> AnonymizedText:
    """Replace every finding using the operator registered for its entity (or ``default``).

    Findings must not overlap (the detector guarantees this). O(n + m).
    """
    ops = dict(operators or {})
    fallback: Operator = default if default is not None else Redact()
    ordered = sorted(findings, key=lambda f: f.start)
    for prev, cur in itertools.pairwise(ordered):
        if cur.start < prev.end:
            raise InvalidInputError("findings overlap; resolve overlaps before anonymizing")
    parts: list[str] = []
    replacements: list[Replacement] = []
    cursor = 0
    out_len = 0
    for f in ordered:
        if f.start < cursor or f.end > len(text) or text[f.start : f.end] != f.text:
            raise InvalidInputError("finding offsets do not match the text")
        parts.append(text[cursor : f.start])
        out_len += f.start - cursor
        op = ops.get(f.entity, fallback)
        replacement = op.apply(f)
        parts.append(replacement)
        replacements.append(Replacement(f.entity, out_len, out_len + len(replacement), type(op).__name__))
        out_len += len(replacement)
        cursor = f.end
    parts.append(text[cursor:])
    return AnonymizedText("".join(parts), tuple(replacements))


def detokenize_text(text: str, tokenizer: Tokenizer) -> str:
    """Reverse tagged tokens (``[[ENTITY:token]]``) back to their original values."""

    def _restore(match: re.Match[str]) -> str:
        return tokenizer.detokenize(match.group(2), match.group(1))

    return TAG_PATTERN.sub(_restore, text)
