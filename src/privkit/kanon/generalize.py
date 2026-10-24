"""Full-domain generalization: search the lattice of hierarchy levels for the
least-generalized assignment that makes the table k-anonymous, optionally
suppressing a bounded fraction of outlier records.

The lattice has prod(h_i + 1) nodes for QI hierarchies of heights h_i. Nodes are
visited in increasing order of precision loss (Sweeney's Prec metric, the mean
of level/height over QIs), which is monotone along lattice edges, so the first
feasible node found is a minimum-loss solution. Each feasibility check is O(n)
over precomputed generalized columns; total worst case O(n * prod(h_i + 1)).
"""

from __future__ import annotations

import itertools
import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from privkit.errors import ConfigurationError, InvalidInputError
from privkit.kanon.hierarchy import Hierarchy
from privkit.kanon.metrics import Row

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GeneralizationResult:
    rows: list[dict[str, str]]
    levels: dict[str, int]
    suppressed: int
    precision_loss: float
    nodes_checked: int

    def to_dict(self) -> dict[str, object]:
        return {
            "levels": dict(self.levels),
            "suppressed": self.suppressed,
            "precision_loss": round(self.precision_loss, 4),
            "nodes_checked": self.nodes_checked,
            "n_output_rows": len(self.rows),
        }


def generalize_to_k(
    rows: Sequence[Row],
    hierarchies: Mapping[str, Hierarchy],
    k: int,
    *,
    max_suppression: float = 0.0,
) -> GeneralizationResult:
    """Return the minimum-precision-loss full-domain generalization achieving k-anonymity.

    ``hierarchies`` maps each quasi-identifier to its hierarchy. Records in
    classes smaller than k are suppressed (removed) if their number does not
    exceed ``max_suppression * len(rows)``.
    """
    if k < 1:
        raise InvalidInputError("k must be >= 1")
    if not 0 <= max_suppression < 1:
        raise ConfigurationError("max_suppression must be in [0, 1)")
    if not hierarchies:
        raise ConfigurationError("at least one quasi-identifier hierarchy is required")
    qis = list(hierarchies)
    n = len(rows)
    for q in qis:
        if any(q not in r for r in rows):
            raise InvalidInputError(f"quasi-identifier column {q!r} missing from some rows")
    heights = [hierarchies[q].height for q in qis]
    # Precompute every generalized column once: columns[qi_index][level] -> list of values.
    columns = [
        [[hierarchies[q].generalize(r[q], lvl) for r in rows] for lvl in range(h + 1)]
        for q, h in zip(qis, heights, strict=True)
    ]
    budget = int(max_suppression * n)
    nodes = sorted(
        itertools.product(*(range(h + 1) for h in heights)),
        key=lambda node: (sum(lvl / h for lvl, h in zip(node, heights, strict=True)), node),
    )
    for checked, node in enumerate(nodes, start=1):
        keys = list(zip(*(columns[i][lvl] for i, lvl in enumerate(node)), strict=True)) if n else []
        sizes = Counter(keys)
        small = sum(c for c in sizes.values() if c < k)
        if small <= budget:
            out: list[dict[str, str]] = []
            for row, key in zip(rows, keys, strict=True):
                if sizes[key] < k:
                    continue
                new = dict(row)
                new.update(zip(qis, key, strict=True))
                out.append(new)
            loss = sum(lvl / h for lvl, h in zip(node, heights, strict=True)) / len(qis)
            logger.info("k=%d reached at levels %s after %d nodes (suppressed %d)", k, node, checked, small)
            return GeneralizationResult(out, dict(zip(qis, node, strict=True)), small, loss, checked)
    raise InvalidInputError(f"k={k} is unreachable even at full generalization (only {n} rows)")
