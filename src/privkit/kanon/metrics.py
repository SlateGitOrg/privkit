"""Re-identification risk metrics over quasi-identifiers: k-anonymity, l-diversity, t-closeness.

Definitions (Sweeney 2002; Machanavajjhala et al. 2007; Li et al. 2007):

* An *equivalence class* is the set of records sharing all quasi-identifier values.
* *k-anonymity*: every class has at least k records. The table's k is the
  smallest class size.
* *distinct l-diversity*: every class has at least l distinct sensitive values;
  *entropy l-diversity* uses exp(entropy) instead of the distinct count.
* *t-closeness*: the distribution of the sensitive attribute in each class is
  within distance t of its distribution in the whole table (equal-distance EMD,
  i.e. total variation, for categorical values; ordered EMD for numeric values).

Complexity: O(n) to build classes (hashing) plus O(n log n) for ordered EMD.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from privkit.errors import InvalidInputError

Row = Mapping[str, str]


def equivalence_classes(rows: Sequence[Row], quasi_identifiers: Sequence[str]) -> dict[tuple[str, ...], list[int]]:
    """Map each QI-value tuple to the row indices sharing it."""
    if not quasi_identifiers:
        raise InvalidInputError("at least one quasi-identifier is required")
    classes: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for i, row in enumerate(rows):
        try:
            key = tuple(row[q] for q in quasi_identifiers)
        except KeyError as exc:
            raise InvalidInputError(f"row {i} lacks quasi-identifier column {exc.args[0]!r}") from None
        classes[key].append(i)
    return dict(classes)


def _is_numeric(values: Sequence[str]) -> bool:
    try:
        for v in values:
            float(v)
    except ValueError:
        return False
    return bool(values)


def total_variation(p: Mapping[str, float], q: Mapping[str, float]) -> float:
    keys = set(p) | set(q)
    return 0.5 * sum(abs(p.get(k, 0.0) - q.get(k, 0.0)) for k in keys)


def ordered_emd(p: Mapping[str, float], q: Mapping[str, float], order: Sequence[str]) -> float:
    """EMD with ground distance |i - j| / (m - 1) over an ordered domain of m values."""
    m = len(order)
    if m <= 1:
        return 0.0
    cumulative, total = 0.0, 0.0
    for v in order[:-1]:
        cumulative += p.get(v, 0.0) - q.get(v, 0.0)
        total += abs(cumulative)
    return total / (m - 1)


def _distribution(values: Sequence[str]) -> dict[str, float]:
    counts = Counter(values)
    n = len(values)
    return {k: c / n for k, c in counts.items()}


@dataclass(frozen=True)
class SensitiveReport:
    attribute: str
    distinct_l: int
    entropy_l: float
    t_closeness: float
    numeric: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "attribute": self.attribute,
            "distinct_l": self.distinct_l,
            "entropy_l": round(self.entropy_l, 4),
            "t_closeness": round(self.t_closeness, 4),
            "numeric": self.numeric,
        }


@dataclass(frozen=True)
class RiskReport:
    n_records: int
    quasi_identifiers: tuple[str, ...]
    n_classes: int
    k: int
    target_k: int | None
    violating_classes: int
    records_at_risk: int
    unique_records: int
    prosecutor_risk_max: float
    prosecutor_risk_avg: float
    sensitive: tuple[SensitiveReport, ...] = field(default=())
    smallest_classes: tuple[tuple[tuple[str, ...], int], ...] = field(default=())

    @property
    def satisfies_k(self) -> bool:
        return self.target_k is None or self.k >= self.target_k

    def to_dict(self, *, include_class_keys: bool = False) -> dict[str, object]:
        """Serializable summary. Class keys are QI values, so they are omitted unless requested."""
        out: dict[str, object] = {
            "n_records": self.n_records,
            "quasi_identifiers": list(self.quasi_identifiers),
            "n_classes": self.n_classes,
            "k": self.k,
            "target_k": self.target_k,
            "satisfies_k": self.satisfies_k,
            "violating_classes": self.violating_classes,
            "records_at_risk": self.records_at_risk,
            "unique_records": self.unique_records,
            "prosecutor_risk_max": round(self.prosecutor_risk_max, 4),
            "prosecutor_risk_avg": round(self.prosecutor_risk_avg, 4),
            "sensitive": [s.to_dict() for s in self.sensitive],
        }
        if include_class_keys:
            out["smallest_classes"] = [{"key": list(k), "size": n} for k, n in self.smallest_classes]
        return out


def assess(
    rows: Sequence[Row],
    quasi_identifiers: Sequence[str],
    *,
    sensitive: Sequence[str] = (),
    k: int | None = None,
    show_smallest: int = 5,
) -> RiskReport:
    """Compute k-anonymity, re-identification risk and (optionally) l-diversity / t-closeness."""
    if k is not None and k < 1:
        raise InvalidInputError("k must be >= 1")
    n = len(rows)
    if n == 0:
        return RiskReport(0, tuple(quasi_identifiers), 0, 0, k, 0, 0, 0, 0.0, 0.0)
    classes = equivalence_classes(rows, quasi_identifiers)
    sizes = {key: len(idx) for key, idx in classes.items()}
    k_min = min(sizes.values())
    target = k if k is not None else 1
    violating = [key for key, s in sizes.items() if s < target]
    sens_reports = []
    for attr in sensitive:
        try:
            all_values = [row[attr] for row in rows]
        except KeyError:
            raise InvalidInputError(f"sensitive column {attr!r} is missing") from None
        numeric = _is_numeric(all_values)
        order = sorted(set(all_values), key=float) if numeric else sorted(set(all_values))
        global_dist = _distribution(all_values)
        distinct_l, entropy_l, t_max = math.inf, math.inf, 0.0
        for idx in classes.values():
            values = [all_values[i] for i in idx]
            dist = _distribution(values)
            distinct_l = min(distinct_l, len(dist))
            entropy = -sum(p * math.log(p) for p in dist.values())
            entropy_l = min(entropy_l, math.exp(entropy))
            t = ordered_emd(dist, global_dist, order) if numeric else total_variation(dist, global_dist)
            t_max = max(t_max, t)
        sens_reports.append(SensitiveReport(attr, int(distinct_l), float(entropy_l), t_max, numeric))
    smallest = tuple(sorted(sizes.items(), key=lambda kv: (kv[1], kv[0]))[:show_smallest])
    return RiskReport(
        n_records=n,
        quasi_identifiers=tuple(quasi_identifiers),
        n_classes=len(classes),
        k=k_min,
        target_k=k,
        violating_classes=len(violating),
        records_at_risk=sum(sizes[key] for key in violating),
        unique_records=sum(1 for s in sizes.values() if s == 1),
        prosecutor_risk_max=1 / k_min,
        prosecutor_risk_avg=len(classes) / n,
        sensitive=tuple(sens_reports),
        smallest_classes=smallest,
    )
