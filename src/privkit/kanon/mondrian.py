"""Mondrian multidimensional k-anonymization (LeFevre, DeWitt & Ramakrishnan, ICDE 2006).

Records are recursively split at the median of the quasi-identifier with the
widest normalized range, as long as both halves keep at least k records. Each
final partition becomes one equivalence class: numeric QIs are generalized to
``[min-max]`` ranges and categorical QIs to the ``|``-joined set of their values.

Numeric QIs are ordered numerically; categorical ones lexicographically
(the "relaxed ordering" variant, which needs no hierarchy).

Complexity: O(n log^2 n) expected (sorting at each of O(log n) recursion levels).
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass

from privkit.errors import InvalidInputError
from privkit.kanon.metrics import Row


@dataclass(frozen=True)
class MondrianResult:
    rows: list[dict[str, str]]
    n_partitions: int
    discernibility: int  # sum of squared class sizes (lower is better)
    ncp: float  # normalized certainty penalty in [0, 1] (lower is better)

    def to_dict(self) -> dict[str, object]:
        return {
            "n_partitions": self.n_partitions,
            "discernibility": self.discernibility,
            "ncp": round(self.ncp, 4),
            "n_output_rows": len(self.rows),
        }


def _numeric(rows: Sequence[Row], q: str) -> bool:
    try:
        for r in rows:
            float(r[q])
    except ValueError:
        return False
    return True


def mondrian(
    rows: Sequence[Row],
    quasi_identifiers: Sequence[str],
    k: int,
    *,
    categorical: Collection[str] = (),
) -> MondrianResult:
    """k-anonymize ``rows`` over ``quasi_identifiers``.

    Columns whose values all parse as numbers are treated as numeric unless
    listed in ``categorical`` (useful for codes such as ZIP codes, where a range
    is less meaningful than a set).
    """
    if k < 1:
        raise InvalidInputError("k must be >= 1")
    if not quasi_identifiers:
        raise InvalidInputError("at least one quasi-identifier is required")
    n = len(rows)
    if n < k:
        raise InvalidInputError(f"cannot reach k={k} with only {n} rows")
    for q in quasi_identifiers:
        if any(q not in r for r in rows):
            raise InvalidInputError(f"quasi-identifier column {q!r} missing from some rows")
    numeric = {q: q not in categorical and _numeric(rows, q) for q in quasi_identifiers}
    # Map every QI to a float coordinate: numeric values as-is, categorical values
    # to their rank in sorted order. Splitting then works uniformly on floats.
    coords: dict[str, list[float]] = {}
    for q in quasi_identifiers:
        if numeric[q]:
            coords[q] = [float(r[q]) for r in rows]
        else:
            rank = {v: float(i) for i, v in enumerate(sorted({r[q] for r in rows}))}
            coords[q] = [rank[r[q]] for r in rows]

    def span(part: Sequence[int], q: str) -> float:
        vals = coords[q]
        return max(vals[i] for i in part) - min(vals[i] for i in part)

    global_span = {q: span(range(n), q) or 1.0 for q in quasi_identifiers}
    finished: list[list[int]] = []
    stack: list[list[int]] = [list(range(n))]
    while stack:
        part = stack.pop()
        spans = {q: span(part, q) for q in quasi_identifiers}
        for q in sorted(quasi_identifiers, key=lambda d: -spans[d] / global_span[d]):
            if spans[q] == 0:
                continue
            vals = coords[q]
            ordered = sorted(part, key=vals.__getitem__)
            median = vals[ordered[(len(ordered) - 1) // 2]]
            left = [i for i in ordered if vals[i] <= median]
            right = ordered[len(left) :]
            if len(left) >= k and len(right) >= k:  # strict Mondrian: both halves stay k-anonymous
                stack.extend([left, right])
                break
        else:
            finished.append(part)

    out: list[dict[str, str]] = []
    ncp_total = 0.0
    for part in finished:
        summary: dict[str, str] = {}
        for q in quasi_identifiers:
            ncp_total += len(part) * span(part, q) / global_span[q]
            if numeric[q]:
                # Report the original strings at the extremes (keeps formatting such as leading zeros).
                lo_i = min(part, key=coords[q].__getitem__)
                hi_i = max(part, key=coords[q].__getitem__)
                lo, hi = rows[lo_i][q], rows[hi_i][q]
                summary[q] = lo if coords[q][lo_i] == coords[q][hi_i] else f"[{lo}-{hi}]"
            else:
                summary[q] = "|".join(sorted({rows[i][q] for i in part}))
        for i in part:
            new = dict(rows[i])
            new.update(summary)
            out.append(new)
    return MondrianResult(
        rows=out,
        n_partitions=len(finished),
        discernibility=sum(len(p) ** 2 for p in finished),
        ncp=ncp_total / (n * len(quasi_identifiers)),
    )
