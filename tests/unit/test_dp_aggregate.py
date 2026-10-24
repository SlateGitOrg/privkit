from __future__ import annotations

import math
import random
from collections import Counter

import pytest

from privkit.dp import (
    ContributionBounds,
    DPAggregator,
    Metric,
    NoiseFamily,
    PrivacyAccountant,
    bound_contributions,
    selection_threshold,
)
from privkit.errors import BudgetExceededError, ConfigurationError

ALL = "__all__"


def agg(eps: float = 100.0, delta: float = 1e-3, seed: int = 0, composition: str = "basic") -> DPAggregator:
    return DPAggregator(PrivacyAccountant(eps, delta, composition), rng=random.Random(seed))


def test_bound_contributions_limits_each_unit() -> None:
    records = [("heavy", f"p{i}", 1.0) for i in range(10) for _ in range(5)] + [("light", "p0", 2.0)]
    kept = bound_contributions(records, ContributionBounds(max_partitions=3, max_per_partition=2), random.Random(1))
    heavy = [r for r in kept if r[0] == "heavy"]
    assert len({r[1] for r in heavy}) == 3
    assert max(Counter(r[1] for r in heavy).values()) == 2
    assert ("light", "p0", 2.0) in kept
    with pytest.raises(ConfigurationError):
        ContributionBounds(0, 1)


def test_count_with_public_partitions_is_accurate_at_high_epsilon() -> None:
    records = [(u, "a" if u < 700 else "b", 1.0) for u in range(1000)]
    res = agg().count(records, epsilon=50.0, public_partitions=["a", "b", "c"])
    assert res.metric is Metric.COUNT and not res.selected_partitions
    values = {k: v.value for k, v in res.partitions.items()}
    assert abs(values["a"] - 700) <= 2 and abs(values["b"] - 300) <= 2 and values["c"] <= 2
    assert res.mechanisms == ("discrete_laplace",)
    assert res.to_rows()[0]["partition"] == "a"


def test_sum_and_mean_clamp_values() -> None:
    records = [(u, ALL, 1_000_000.0 if u == 0 else 10.0) for u in range(500)]
    a = agg()
    total = a.sum(records, lower=0, upper=20, epsilon=50.0, public_partitions=[ALL]).partitions[ALL].value
    assert abs(total - (499 * 10 + 20)) < 20  # the outlier was clamped to 20
    mean = a.mean(records, lower=0, upper=20, epsilon=50.0, public_partitions=[ALL]).partitions[ALL]
    assert abs(mean.value - 10.0) < 0.5 and 0 <= mean.value <= 20 and mean.ci95 > 0


def test_mean_of_empty_partition_stays_in_range() -> None:
    res = agg().mean([], lower=5, upper=7, epsilon=1.0, public_partitions=["x"])
    assert 5 <= res.partitions["x"].value <= 7


def test_gaussian_noise_family() -> None:
    records = [(u, ALL, float(u % 10)) for u in range(2000)]
    a = agg(eps=100, delta=1e-3)
    res = a.sum(records, lower=0, upper=9.5, epsilon=5.0, delta=1e-5, noise="gaussian", public_partitions=[ALL])
    assert res.noise is NoiseFamily.GAUSSIAN and res.mechanisms == ("gaussian",)
    assert abs(res.partitions[ALL].value - sum(u % 10 for u in range(2000))) < 60
    ints = a.count(records, epsilon=5.0, delta=1e-5, noise="gaussian", public_partitions=[ALL])
    assert ints.mechanisms == ("discrete_gaussian",)
    with pytest.raises(ConfigurationError):
        a.count(records, epsilon=1.0, noise="gaussian", public_partitions=[ALL])


def test_private_partition_selection_hides_rare_keys() -> None:
    # 'big' has 500 distinct users; each 'rare-i' key belongs to exactly one user.
    records = [(u, "big", 1.0) for u in range(500)] + [(1000 + i, f"rare-{i}", 1.0) for i in range(300)]
    res = agg(eps=10, delta=1e-3).count(records, epsilon=1.0, delta=1e-6)
    assert res.selected_partitions and "big" in res.partitions
    assert not any(str(k).startswith("rare-") for k in res.partitions)
    assert res.cost.delta == pytest.approx(1e-6)


def test_selection_requires_delta() -> None:
    with pytest.raises(ConfigurationError):
        agg().count([(1, "a", 1.0)], epsilon=1.0)


def test_selection_threshold_math() -> None:
    eps, delta, l0 = 1.0, 1e-6, 3
    scale, k = selection_threshold(eps, delta, l0)
    q = math.exp(-1 / float(scale))
    assert q**k / (1 + q) <= delta / l0  # singleton released w.p. <= delta / L0
    assert q ** (k - 1) / (1 + q) > delta / l0  # and k is the smallest such threshold
    with pytest.raises(ConfigurationError):
        selection_threshold(1.0, 0.0, 1)


def test_budget_is_charged_once_and_refusal_releases_nothing() -> None:
    acct = PrivacyAccountant(1.0, 1e-5)
    a = DPAggregator(acct, rng=random.Random(3))
    records = [(u, "x", 1.0) for u in range(100)]
    a.count(records, epsilon=0.6, public_partitions=["x"])
    with pytest.raises(BudgetExceededError):
        a.count(records, epsilon=0.6, public_partitions=["x"])
    assert len(acct.ledger) == 1 and acct.spent().epsilon == pytest.approx(0.6)


def test_mean_splits_budget_into_two_charges() -> None:
    acct = PrivacyAccountant(1.0)
    DPAggregator(acct, rng=random.Random(4)).mean(
        [(1, "x", 1.0)], lower=0, upper=2, epsilon=1.0, public_partitions=["x"]
    )
    assert [c.label for c in acct.ledger] == ["mean:count", "mean:centered_sum"]
    assert [c.cost.epsilon for c in acct.ledger] == [0.5, 0.5]


def test_selection_charges_are_split() -> None:
    acct = PrivacyAccountant(3.0, 1e-5)
    DPAggregator(acct, rng=random.Random(5)).count([(1, "x", 1.0)], epsilon=0.9, delta=1e-6, label="q")
    labels = {c.label: c.cost for c in acct.ledger}
    assert labels["q:partition_selection"].epsilon == pytest.approx(0.3)
    assert labels["q:count"].epsilon == pytest.approx(0.6)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"epsilon": 0.0},
        {"epsilon": -1.0},
        {"epsilon": 1.0, "selection_fraction": 1.5, "delta": 1e-6},
    ],
)
def test_aggregate_validation(kwargs: dict[str, float]) -> None:
    with pytest.raises(ConfigurationError):
        agg().count([(1, "x", 1.0)], **kwargs)  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError):
        agg().sum([(1, "x", 1.0)], lower=5, upper=5, epsilon=1.0, public_partitions=["x"])


def test_contribution_bounds_scale_noise() -> None:
    a = agg()
    narrow = a.count([], epsilon=1.0, public_partitions=["x"])
    wide = a.count([], epsilon=1.0, public_partitions=["x"], bounds=ContributionBounds(4, 2))
    assert wide.partitions["x"].noise_std > 6 * narrow.partitions["x"].noise_std


@pytest.mark.parametrize("noise", ["laplace", "gaussian"])
@pytest.mark.parametrize("integer", [False, True])
def test_sum_mechanism_does_not_depend_on_the_records(noise: str, integer: bool) -> None:
    # Neighbouring datasets: D has only integer values, D' adds one user with a non-integer value.
    # If the mechanism were chosen from the data, the output's integrality would reveal which one ran.
    d = [(u, ALL, 3.0) for u in range(50)]
    d_prime = [*d, (50, ALL, 2.5)]
    kw = {"lower": 0, "upper": 10, "epsilon": 1.0, "delta": 1e-5, "noise": noise, "public_partitions": [ALL]}
    seen = set()
    for records in (d, d_prime):
        res = agg().sum(records, integer=integer, **kw)  # type: ignore[arg-type]
        seen.add(res.mechanisms)
        value = res.partitions[ALL].value
        if integer:
            assert value.is_integer()
    assert len(seen) == 1
    expected = {
        (False, "laplace"): ("laplace",),
        (False, "gaussian"): ("gaussian",),
        (True, "laplace"): ("discrete_laplace",),
        (True, "gaussian"): ("discrete_gaussian",),
    }[(integer, noise)]
    assert seen == {expected}


def test_continuous_sum_outputs_are_not_integer_on_integer_data() -> None:
    # Default sums are continuous, so an integer result no longer signals "all values were integers".
    d = [(u, ALL, 3.0) for u in range(50)]
    values = [
        agg(seed=s).sum(d, lower=0, upper=10, epsilon=1.0, public_partitions=[ALL]).partitions[ALL].value
        for s in range(5)
    ]
    assert not any(v.is_integer() for v in values)


def test_integer_sum_rounds_clamped_values_and_needs_integer_bounds() -> None:
    records = [(0, ALL, 2.4), (1, ALL, 2.6), (2, ALL, 99.0)]
    res = agg().sum(records, lower=0, upper=10, epsilon=100.0, public_partitions=[ALL], integer=True)
    assert res.partitions[ALL].value == pytest.approx(2 + 3 + 10, abs=1)
    with pytest.raises(ConfigurationError):
        agg().sum(records, lower=0, upper=9.5, epsilon=1.0, public_partitions=[ALL], integer=True)
