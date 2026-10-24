"""Column-level PII discovery for tabular data (CSV/JSONL rows)."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from privkit.pii.detector import Detector
from privkit.pii.model import Entity

# Header keywords -> the entity they suggest. Used as context and as a reported hint.
HEADER_HINTS: Mapping[str, Entity] = {
    "email": Entity.EMAIL, "mail": Entity.EMAIL,
    "phone": Entity.PHONE, "mobile": Entity.PHONE, "tel": Entity.PHONE, "cell": Entity.PHONE,
    "card": Entity.CREDIT_CARD, "pan": Entity.CREDIT_CARD, "cc": Entity.CREDIT_CARD,
    "ssn": Entity.US_SSN, "social": Entity.US_SSN,
    "iban": Entity.IBAN,
    "ip": Entity.IP_ADDRESS,
    "mac": Entity.MAC_ADDRESS,
    "routing": Entity.US_ABA_ROUTING, "aba": Entity.US_ABA_ROUTING,
    "aadhaar": Entity.IN_AADHAAR,
    "nhs": Entity.UK_NHS,
    "dob": Entity.DATE_OF_BIRTH, "birth": Entity.DATE_OF_BIRTH, "birthday": Entity.DATE_OF_BIRTH,
    "name": Entity.PERSON,
}  # fmt: skip

_SPLIT = re.compile(r"[^a-z0-9]+")


def header_words(column: str) -> list[str]:
    """``"customer_DOB"`` -> ``["customer", "dob"]``."""
    return [w for w in _SPLIT.split(column.lower()) if w]


@dataclass(frozen=True)
class ColumnReport:
    column: str
    n_values: int
    n_non_empty: int
    entity_counts: dict[str, int] = field(default_factory=dict)
    dominant: str | None = None
    prevalence: float = 0.0
    header_hint: str | None = None

    @property
    def is_pii(self) -> bool:
        return self.dominant is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "column": self.column,
            "n_values": self.n_values,
            "n_non_empty": self.n_non_empty,
            "entity_counts": dict(self.entity_counts),
            "dominant": self.dominant,
            "prevalence": round(self.prevalence, 4),
            "header_hint": self.header_hint,
        }


def scan_columns(
    rows: Sequence[Mapping[str, str]],
    detector: Detector,
    *,
    sample_size: int | None = 2000,
    min_prevalence: float = 0.3,
) -> list[ColumnReport]:
    """Classify each column by the entity found in the largest share of its non-empty cells.

    The first ``sample_size`` rows are scanned (``None`` = all). A column is
    labeled with its dominant entity when that entity appears in at least
    ``min_prevalence`` of non-empty cells. Complexity O(rows x columns x cell length).
    """
    sample = rows if sample_size is None else rows[:sample_size]
    columns: list[str] = []
    for row in sample:
        for col in row:
            if col not in columns:
                columns.append(col)
    reports = []
    for col in columns:
        words = header_words(col)
        hint = next((HEADER_HINTS[w].value for w in words if w in HEADER_HINTS), None)
        counts: Counter[str] = Counter()
        non_empty = 0
        for row in sample:
            value = (row.get(col) or "").strip()
            if not value:
                continue
            non_empty += 1
            for entity in {f.entity for f in detector.analyze(value, context_hint=words)}:
                counts[entity] += 1
        dominant, prevalence = None, 0.0
        if counts and non_empty:
            top, n = counts.most_common(1)[0]
            prevalence = n / non_empty
            if prevalence >= min_prevalence:
                dominant = top
        reports.append(ColumnReport(col, len(sample), non_empty, dict(counts), dominant, prevalence, hint))
    return reports
