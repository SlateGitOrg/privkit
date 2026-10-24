"""Generalization hierarchies for quasi-identifiers.

Level 0 is the original value; each level up is coarser; ``height`` is fully
suppressed (``"*"``).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from privkit.errors import ConfigurationError, InvalidInputError

SUPPRESSED = "*"


class Hierarchy(Protocol):
    @property
    def height(self) -> int: ...

    def generalize(self, value: str, level: int) -> str: ...


def _check_level(level: int, height: int) -> None:
    if not 0 <= level <= height:
        raise InvalidInputError(f"generalization level {level} outside [0, {height}]")


@dataclass(frozen=True)
class IntervalHierarchy:
    """Numeric values bucketed into intervals of increasing width, e.g. widths (5, 10, 20)."""

    widths: Sequence[float]

    def __post_init__(self) -> None:
        if not self.widths or any(w <= 0 for w in self.widths) or list(self.widths) != sorted(self.widths):
            raise ConfigurationError("interval widths must be positive and increasing")

    @property
    def height(self) -> int:
        return len(self.widths) + 1

    def generalize(self, value: str, level: int) -> str:
        _check_level(level, self.height)
        if level == 0:
            return value
        if level == self.height:
            return SUPPRESSED
        try:
            x = float(value)
        except ValueError:
            return SUPPRESSED
        w = self.widths[level - 1]
        lo = math.floor(x / w) * w
        hi = lo + w
        fmt = (lambda v: str(int(v))) if float(w).is_integer() else (lambda v: f"{v:g}")
        return f"[{fmt(lo)}-{fmt(hi)})"


@dataclass(frozen=True)
class MaskingHierarchy:
    """Mask trailing characters one at a time (ZIP 02139 -> 0213* -> 021** ...)."""

    max_masked: int
    char: str = "*"

    def __post_init__(self) -> None:
        if self.max_masked < 1:
            raise ConfigurationError("max_masked must be >= 1")

    @property
    def height(self) -> int:
        return self.max_masked + 1

    def generalize(self, value: str, level: int) -> str:
        _check_level(level, self.height)
        if level == self.height:
            return SUPPRESSED
        if level == 0:
            return value
        keep = max(len(value) - level, 0)
        return value[:keep] + self.char * (len(value) - keep)


@dataclass(frozen=True)
class MappingHierarchy:
    """An explicit taxonomy: ``levels[i]`` maps a level-i value to its level-(i+1) parent."""

    levels: Sequence[Mapping[str, str]]

    def __post_init__(self) -> None:
        if not self.levels:
            raise ConfigurationError("a mapping hierarchy needs at least one level")

    @property
    def height(self) -> int:
        return len(self.levels) + 1

    def generalize(self, value: str, level: int) -> str:
        _check_level(level, self.height)
        if level == self.height:
            return SUPPRESSED
        current = value
        for mapping in self.levels[:level]:
            current = mapping.get(current, SUPPRESSED)
        return current


@dataclass(frozen=True)
class SuppressionHierarchy:
    """Two levels only: original or ``*``."""

    @property
    def height(self) -> int:
        return 1

    def generalize(self, value: str, level: int) -> str:
        _check_level(level, self.height)
        return value if level == 0 else SUPPRESSED


def parse_hierarchy(spec: str) -> Hierarchy:
    """Parse a CLI hierarchy spec: ``interval:5,10,20`` | ``mask:3`` | ``suppress``."""
    kind, _, arg = spec.partition(":")
    try:
        if kind == "interval":
            return IntervalHierarchy(tuple(float(x) for x in arg.split(",")))
        if kind == "mask":
            return MaskingHierarchy(int(arg))
    except ValueError:
        raise ConfigurationError(f"bad hierarchy spec {spec!r}") from None
    if kind == "suppress":
        return SuppressionHierarchy()
    raise ConfigurationError(f"unknown hierarchy kind in {spec!r} (interval:, mask:, suppress)")
