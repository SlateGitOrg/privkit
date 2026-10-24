"""Strict span-level precision / recall / F1 for the PII detector."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from privkit.evaluation.corpus import Document, Span
from privkit.pii.model import Finding


@dataclass
class EntityScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def support(self) -> int:
        return self.tp + self.fn


@dataclass
class EvalReport:
    per_entity: dict[str, EntityScore] = field(default_factory=dict)
    n_docs: int = 0

    @property
    def micro(self) -> EntityScore:
        total = EntityScore()
        for s in self.per_entity.values():
            total.tp += s.tp
            total.fp += s.fp
            total.fn += s.fn
        return total

    def to_dict(self) -> dict[str, object]:
        def row(s: EntityScore) -> dict[str, float | int]:
            return {
                "precision": round(s.precision, 4),
                "recall": round(s.recall, 4),
                "f1": round(s.f1, 4),
                "tp": s.tp,
                "fp": s.fp,
                "fn": s.fn,
                "support": s.support,
            }

        return {
            "n_docs": self.n_docs,
            "micro": row(self.micro),
            "per_entity": {k: row(v) for k, v in sorted(self.per_entity.items())},
        }

    def to_markdown(self) -> str:
        lines = ["| entity | precision | recall | F1 | support |", "|---|---:|---:|---:|---:|"]
        for name, s in sorted(self.per_entity.items()):
            lines.append(f"| {name} | {s.precision:.3f} | {s.recall:.3f} | {s.f1:.3f} | {s.support} |")
        m = self.micro
        lines.append(f"| **micro** | **{m.precision:.3f}** | **{m.recall:.3f}** | **{m.f1:.3f}** | {m.support} |")
        return "\n".join(lines)


def evaluate(
    docs: Sequence[Document],
    predict: Callable[[str], Iterable[Finding]],
    entities: Iterable[str],
) -> EvalReport:
    """Strict matching: a prediction is a true positive iff (entity, start, end) equals a gold span.

    Only ``entities`` are scored, so a regex-only detector is not penalized for
    entity types (PERSON, LOCATION) it does not attempt.
    """
    wanted = frozenset(entities)
    report = EvalReport(per_entity={e: EntityScore() for e in sorted(wanted)}, n_docs=len(docs))
    for doc in docs:
        gold = {s for s in doc.spans if s.entity in wanted}
        pred = {Span(f.entity, f.start, f.end) for f in predict(doc.text) if f.entity in wanted}
        for s in pred & gold:
            report.per_entity[s.entity].tp += 1
        for s in pred - gold:
            report.per_entity[s.entity].fp += 1
        for s in gold - pred:
            report.per_entity[s.entity].fn += 1
    return report
