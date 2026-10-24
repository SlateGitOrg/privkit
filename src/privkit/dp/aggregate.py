"""Differentially private aggregation with bounded user contributions.

Pipeline for one query (count / sum / mean, optionally grouped by a key):

1. **Contribution bounding.** Each privacy unit (for example a user id) keeps at
   most ``max_partitions`` randomly chosen partitions and at most
   ``max_per_partition`` randomly chosen records in each. Values are clamped to
   ``[lower, upper]``. This is what makes the sensitivity finite and known.
2. **Partition selection.** If the set of group keys is not public, keys are
   released only when a noisy count of distinct units clears a threshold
   (Laplace thresholding). This costs part of epsilon *and* needs delta > 0,
   because a key held by a single user would otherwise reveal that user.
3. **Noisy aggregation.** Calibrated noise is added per released partition.
   Integer-valued queries use the exact discrete samplers; real-valued ones use
   the continuous mechanisms.
4. **Accounting.** All charges for the query are recorded atomically in the
   :class:`PrivacyAccountant` *before* any noisy value is returned.

Time O(n + P) for n records and P partitions; memory O(n) for the grouping.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from collections.abc import Hashable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from fractions import Fraction

from privkit.dp._exact import discrete_laplace, rational_at_least
from privkit.dp.accountant import Charge, PrivacyAccountant, charge_for
from privkit.dp.mechanisms import (
    DiscreteGaussianMechanism,
    DiscreteLaplaceMechanism,
    GaussianMechanism,
    LaplaceMechanism,
    Mechanism,
    PrivacyCost,
)
from privkit.dp.rng import secure_rng
from privkit.errors import ConfigurationError

Record = tuple[Hashable, Hashable, float]  # (privacy unit, partition key, value)
ALL = "__all__"


class NoiseFamily(StrEnum):
    LAPLACE = "laplace"  # pure epsilon-DP
    GAUSSIAN = "gaussian"  # (epsilon, delta)-DP


class Metric(StrEnum):
    COUNT = "count"
    SUM = "sum"
    MEAN = "mean"


@dataclass(frozen=True)
class ContributionBounds:
    max_partitions: int = 1
    max_per_partition: int = 1

    def __post_init__(self) -> None:
        if self.max_partitions < 1 or self.max_per_partition < 1:
            raise ConfigurationError("contribution bounds must be >= 1")


@dataclass(frozen=True)
class ReleasedValue:
    value: float
    noise_std: float
    ci95: float  # half-width of an (approximate, for mean) 95% interval around value


@dataclass(frozen=True)
class DPResult:
    metric: Metric
    noise: NoiseFamily
    partitions: dict[Hashable, ReleasedValue]
    cost: PrivacyCost
    bounds: ContributionBounds
    value_range: tuple[float, float] | None
    selected_partitions: bool
    mechanisms: tuple[str, ...] = field(default=())

    def to_rows(self) -> list[dict[str, object]]:
        return [
            {"partition": k, "value": v.value, "noise_std": v.noise_std, "ci95": v.ci95}
            for k, v in sorted(self.partitions.items(), key=lambda kv: str(kv[0]))
        ]


def bound_contributions(records: Iterable[Record], bounds: ContributionBounds, rng: random.Random) -> list[Record]:
    """Keep <= max_partitions partitions per unit and <= max_per_partition records in each (uniformly at random)."""
    per_unit: dict[Hashable, dict[Hashable, list[float]]] = defaultdict(lambda: defaultdict(list))
    for unit, part, value in records:
        per_unit[unit][part].append(value)
    kept: list[Record] = []
    for unit, parts in per_unit.items():
        keys = list(parts)
        if len(keys) > bounds.max_partitions:
            keys = rng.sample(keys, bounds.max_partitions)
        for key in keys:
            values = parts[key]
            if len(values) > bounds.max_per_partition:
                values = rng.sample(values, bounds.max_per_partition)
            kept.extend((unit, key, v) for v in values)
    return kept


def selection_threshold(epsilon: float, delta: float, max_partitions: int) -> tuple[Fraction, int]:
    """Discrete-Laplace scale and integer threshold k for private partition selection.

    A partition is released iff ``distinct_units + Z >= 1 + k`` with Z ~ DLap(L0/eps).
    For a partition only one unit contributes to, P(Z >= k) = q^k / (1 + q) with
    q = exp(-eps/L0); requiring this <= delta/L0 and a union bound over the <= L0
    partitions a unit touches gives (eps, delta)-DP for the released key set.
    """
    if not 0 < delta < 1:
        raise ConfigurationError("private partition selection needs delta in (0, 1)")
    scale = rational_at_least(max_partitions / epsilon)
    q = math.exp(-1 / float(scale))
    k = math.ceil(math.log(delta * (1 + q) / max_partitions) / math.log(q))
    return scale, max(k, 1)


class DPAggregator:
    """Runs DP count/sum/mean queries and charges them to an accountant.

    >>> from privkit.dp import PrivacyAccountant
    >>> import random
    >>> acct = PrivacyAccountant(epsilon=1.0)
    >>> agg = DPAggregator(acct, rng=random.Random(0))  # seeded only for the example
    >>> res = agg.count([(u, "x", 1.0) for u in range(100)], epsilon=0.5, public_partitions=["x"])
    >>> round(acct.spent().epsilon, 3)
    0.5
    """

    def __init__(self, accountant: PrivacyAccountant, rng: random.Random | None = None) -> None:
        self.accountant = accountant
        self.rng = rng if rng is not None else secure_rng()

    # -- public API ------------------------------------------------------------
    def count(
        self,
        records: Iterable[Record],
        *,
        epsilon: float,
        delta: float = 0.0,
        noise: NoiseFamily | str = NoiseFamily.LAPLACE,
        bounds: ContributionBounds | None = None,
        public_partitions: Sequence[Hashable] | None = None,
        selection_fraction: float = 1 / 3,
        label: str = "count",
    ) -> DPResult:
        return self._run(
            Metric.COUNT, records, epsilon, delta, NoiseFamily(noise), bounds or ContributionBounds(), None,
            public_partitions, selection_fraction, label,
        )  # fmt: skip

    def sum(
        self,
        records: Iterable[Record],
        *,
        lower: float,
        upper: float,
        epsilon: float,
        delta: float = 0.0,
        noise: NoiseFamily | str = NoiseFamily.LAPLACE,
        bounds: ContributionBounds | None = None,
        public_partitions: Sequence[Hashable] | None = None,
        selection_fraction: float = 1 / 3,
        label: str = "sum",
    ) -> DPResult:
        return self._run(
            Metric.SUM, records, epsilon, delta, NoiseFamily(noise), bounds or ContributionBounds(), (lower, upper),
            public_partitions, selection_fraction, label,
        )  # fmt: skip

    def mean(
        self,
        records: Iterable[Record],
        *,
        lower: float,
        upper: float,
        epsilon: float,
        delta: float = 0.0,
        noise: NoiseFamily | str = NoiseFamily.LAPLACE,
        bounds: ContributionBounds | None = None,
        public_partitions: Sequence[Hashable] | None = None,
        selection_fraction: float = 1 / 3,
        label: str = "mean",
    ) -> DPResult:
        return self._run(
            Metric.MEAN, records, epsilon, delta, NoiseFamily(noise), bounds or ContributionBounds(), (lower, upper),
            public_partitions, selection_fraction, label,
        )  # fmt: skip

    # -- internals -------------------------------------------------------------
    def _mechanism(
        self, noise: NoiseFamily, epsilon: float, delta: float, l1: float, l2: float, integer: bool
    ) -> Mechanism:
        if noise is NoiseFamily.LAPLACE:
            if integer and float(l1).is_integer():
                return DiscreteLaplaceMechanism(epsilon, int(l1), rng=self.rng)
            return LaplaceMechanism(epsilon, l1, rng=self.rng)
        if delta <= 0:
            raise ConfigurationError("Gaussian noise needs delta > 0")
        if integer and float(l2).is_integer():
            return DiscreteGaussianMechanism(epsilon, delta, int(l2), rng=self.rng)
        return GaussianMechanism(epsilon, delta, l2, rng=self.rng)

    def _run(
        self,
        metric: Metric,
        records: Iterable[Record],
        epsilon: float,
        delta: float,
        noise: NoiseFamily,
        bounds: ContributionBounds,
        value_range: tuple[float, float] | None,
        public_partitions: Sequence[Hashable] | None,
        selection_fraction: float,
        label: str,
    ) -> DPResult:
        PrivacyCost(epsilon, delta)  # validates ranges
        if epsilon <= 0:
            raise ConfigurationError("epsilon must be positive")
        if value_range is not None:
            lo, hi = value_range
            if not (math.isfinite(lo) and math.isfinite(hi) and lo < hi):
                raise ConfigurationError("value range must satisfy lower < upper (both finite)")
        if not 0 < selection_fraction < 1:
            raise ConfigurationError("selection_fraction must be in (0, 1)")

        kept = bound_contributions(records, bounds, self.rng)
        select = public_partitions is None
        eps_query, delta_query = epsilon, delta
        eps_sel = delta_sel = 0.0
        if select:
            if delta <= 0:
                raise ConfigurationError(
                    "partition keys are not public: pass public_partitions, or give delta > 0 for private selection"
                )
            eps_sel = epsilon * selection_fraction
            eps_query = epsilon - eps_sel
            delta_sel = delta / 2 if noise is NoiseFamily.GAUSSIAN else delta
            delta_query = delta - delta_sel if noise is NoiseFamily.GAUSSIAN else 0.0

        # Group bounded records per partition.
        counts: dict[Hashable, int] = defaultdict(int)
        sums: dict[Hashable, float] = defaultdict(float)
        units: dict[Hashable, set[Hashable]] = defaultdict(set)
        lo, hi = value_range if value_range is not None else (0.0, 0.0)
        mid = (lo + hi) / 2
        for unit, part, value in kept:
            counts[part] += 1
            units[part].add(unit)
            if metric is not Metric.COUNT:
                clamped = min(max(value, lo), hi)
                sums[part] += clamped - mid if metric is Metric.MEAN else clamped

        l0, linf = bounds.max_partitions, bounds.max_per_partition
        mechs: list[tuple[str, Mechanism]] = []
        if metric is Metric.COUNT:
            mechs.append(("count", self._mechanism(noise, eps_query, delta_query, l0 * linf, math.sqrt(l0) * linf, True)))
        elif metric is Metric.SUM:
            m = linf * max(abs(lo), abs(hi))
            integer = float(lo).is_integer() and float(hi).is_integer() and all(float(v).is_integer() for _, _, v in kept)
            mechs.append(("sum", self._mechanism(noise, eps_query, delta_query, l0 * m, math.sqrt(l0) * m, integer)))
        else:
            half = linf * (hi - lo) / 2
            e2, d2 = eps_query / 2, delta_query / 2
            mechs.append(("count", self._mechanism(noise, e2, d2, l0 * linf, math.sqrt(l0) * linf, True)))
            mechs.append(("centered_sum", self._mechanism(noise, e2, d2, l0 * half, math.sqrt(l0) * half, False)))

        charges: list[Charge] = [charge_for(mech, f"{label}:{part}") for part, mech in mechs]
        sel_scale: Fraction | None = None
        sel_k = 0
        if select:
            sel_scale, sel_k = selection_threshold(eps_sel, delta_sel, l0)
            charges.append(Charge(f"{label}:partition_selection", "laplace_threshold", PrivacyCost(eps_sel, delta_sel)))
        cost = self.accountant.charge(*charges)  # raises before any noisy value exists

        if select:
            assert sel_scale is not None
            partitions = [p for p in units if len(units[p]) + discrete_laplace(sel_scale, self.rng) >= 1 + sel_k]
        else:
            partitions = list(dict.fromkeys(public_partitions or ()))

        released: dict[Hashable, ReleasedValue] = {}
        for p in partitions:
            released[p] = self._release(metric, mechs, counts.get(p, 0), sums.get(p, 0.0), lo, hi, mid)
        return DPResult(
            metric, noise, released, cost, bounds, value_range, select, tuple(m.name for _, m in mechs)
        )

    @staticmethod
    def _release(
        metric: Metric,
        mechs: list[tuple[str, Mechanism]],
        count: int,
        total: float,
        lo: float,
        hi: float,
        mid: float,
    ) -> ReleasedValue:
        if metric is Metric.COUNT:
            mech = mechs[0][1]
            # Post-processing (rounding, clamping at zero) cannot weaken DP.
            return ReleasedValue(float(max(round(mech.release(count)), 0)), mech.std, mech.ci_halfwidth())
        if metric is Metric.SUM:
            mech = mechs[0][1]
            return ReleasedValue(mech.release(total), mech.std, mech.ci_halfwidth())
        count_mech, sum_mech = mechs[0][1], mechs[1][1]
        noisy_count = max(count_mech.release(count), 1.0)
        noisy_sum = sum_mech.release(total)
        mean = min(max(mid + noisy_sum / noisy_count, lo), hi)
        # Delta-method approximation of the noise std of the ratio (computed from noisy values only).
        std = math.sqrt(sum_mech.std**2 + (noisy_sum / noisy_count) ** 2 * count_mech.std**2) / noisy_count
        return ReleasedValue(mean, std, 1.96 * std)
