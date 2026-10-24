"""Statistical tests: every DP sampler must produce the distribution its privacy proof assumes.

Seeds are fixed, so each test is deterministic; the significance level (1e-3)
would make a correct sampler fail by chance in at most 0.1% of seeds.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from fractions import Fraction

import pytest
from scipy import stats

from privkit.dp import DiscreteGaussianMechanism, DiscreteLaplaceMechanism, GaussianMechanism, LaplaceMechanism
from privkit.dp._exact import bernoulli, bernoulli_exp, discrete_gaussian, discrete_laplace, rational_at_least

ALPHA = 1e-3
N = 20_000


def _chi_square_vs_pmf(samples: list[int], pmf: dict[int, float]) -> float:
    """Chi-square GOF p-value; tail bins are pooled so every expected count is >= 5."""
    n = len(samples)
    counts = Counter(samples)
    support = sorted(pmf)
    observed, expected = [], []
    tail_obs, tail_exp = 0.0, 0.0
    for z in support:
        e = pmf[z] * n
        if e >= 5:
            observed.append(counts.get(z, 0))
            expected.append(e)
        else:
            tail_obs += counts.get(z, 0)
            tail_exp += e
    tail_obs += sum(c for z, c in counts.items() if z not in pmf)
    tail_exp += n - sum(expected) - tail_exp
    if tail_exp > 0:
        observed.append(tail_obs)
        expected.append(tail_exp)
    scale = sum(observed) / sum(expected)
    return float(stats.chisquare(observed, [e * scale for e in expected]).pvalue)


def _dlap_pmf(scale: float, radius: int) -> dict[int, float]:
    q = math.exp(-1 / scale)
    c = (1 - q) / (1 + q)
    return {z: c * q ** abs(z) for z in range(-radius, radius + 1)}


def _dgauss_pmf(sigma2: float, radius: int) -> dict[int, float]:
    weights = {z: math.exp(-(z * z) / (2 * sigma2)) for z in range(-radius * 3, radius * 3 + 1)}
    total = sum(weights.values())
    return {z: w / total for z, w in weights.items() if abs(z) <= radius}


@pytest.mark.parametrize("p", [Fraction(1, 3), Fraction(7, 10), Fraction(0), Fraction(1)])
def test_bernoulli_frequency(p: Fraction) -> None:
    rng = random.Random(11)
    hits = sum(bernoulli(p, rng) for _ in range(N))
    assert stats.binomtest(hits, N, float(p)).pvalue > ALPHA if 0 < p < 1 else hits == N * p


@pytest.mark.parametrize("gamma", [Fraction(0), Fraction(3, 10), Fraction(1), Fraction(17, 10), Fraction(3)])
def test_bernoulli_exp_frequency(gamma: Fraction) -> None:
    rng = random.Random(12)
    hits = sum(bernoulli_exp(gamma, rng) for _ in range(N))
    expected = math.exp(-float(gamma))
    if expected == 1.0:
        assert hits == N
    else:
        assert stats.binomtest(hits, N, expected).pvalue > ALPHA


@pytest.mark.parametrize("scale", [Fraction(1, 2), Fraction(2), Fraction(73, 10)])
def test_discrete_laplace_matches_pmf(scale: Fraction) -> None:
    rng = random.Random(13)
    samples = [discrete_laplace(scale, rng) for _ in range(N)]
    pmf = _dlap_pmf(float(scale), radius=int(12 * float(scale)) + 3)
    assert _chi_square_vs_pmf(samples, pmf) > ALPHA
    assert abs(sum(samples) / N) < 6 * math.sqrt(2) * float(scale) / math.sqrt(N) + 0.05


@pytest.mark.parametrize("sigma2", [Fraction(1), Fraction(4), Fraction(1024, 100)])
def test_discrete_gaussian_matches_pmf(sigma2: Fraction) -> None:
    rng = random.Random(14)
    samples = [discrete_gaussian(sigma2, rng) for _ in range(N)]
    pmf = _dgauss_pmf(float(sigma2), radius=int(6 * math.sqrt(float(sigma2))) + 2)
    assert _chi_square_vs_pmf(samples, pmf) > ALPHA
    var = sum(s * s for s in samples) / N
    assert var == pytest.approx(float(sigma2), rel=0.06)


@pytest.mark.parametrize(("epsilon", "sensitivity"), [(0.5, 1.0), (1.0, 3.0), (2.0, 0.25)])
def test_laplace_noise_ks(epsilon: float, sensitivity: float) -> None:
    mech = LaplaceMechanism(epsilon, sensitivity, rng=random.Random(15))
    samples = [mech.noise() for _ in range(N)]
    assert stats.kstest(samples, stats.laplace(scale=sensitivity / epsilon).cdf).pvalue > ALPHA
    emp_std = math.sqrt(sum(s * s for s in samples) / N)
    assert emp_std == pytest.approx(mech.std, rel=0.05)


@pytest.mark.parametrize(("epsilon", "delta", "sensitivity"), [(1.0, 1e-5, 1.0), (0.3, 1e-6, 2.0)])
def test_gaussian_noise_ks(epsilon: float, delta: float, sensitivity: float) -> None:
    mech = GaussianMechanism(epsilon, delta, sensitivity, rng=random.Random(16))
    samples = [mech.noise() for _ in range(N)]
    assert stats.kstest(samples, stats.norm(scale=mech.sigma).cdf).pvalue > ALPHA


def test_discrete_mechanisms_ci_coverage() -> None:
    for mech in (
        DiscreteLaplaceMechanism(0.7, 2, rng=random.Random(17)),
        DiscreteGaussianMechanism(1.0, 1e-6, 1, rng=random.Random(18)),
        LaplaceMechanism(0.7, 2, rng=random.Random(19)),
        GaussianMechanism(1.0, 1e-6, rng=random.Random(20)),
    ):
        w = mech.ci_halfwidth(0.95)
        inside = sum(abs(mech.noise()) <= w for _ in range(5000)) / 5000
        assert 0.94 <= inside <= 0.985, (mech.name, inside)


def test_empirical_privacy_ratio_discrete_laplace() -> None:
    """Outputs on neighbouring inputs (0 vs 1) differ in probability by at most e^eps per value."""
    eps = 1.0
    m0 = DiscreteLaplaceMechanism(eps, 1, rng=random.Random(21))
    m1 = DiscreteLaplaceMechanism(eps, 1, rng=random.Random(22))
    n = 100_000
    c0 = Counter(int(m0.release(0)) for _ in range(n))
    c1 = Counter(int(m1.release(1)) for _ in range(n))
    for z in range(-3, 5):
        if c0[z] > 2000 and c1[z] > 2000:
            ratio = c1[z] / c0[z]
            assert math.exp(-eps) * 0.9 <= ratio <= math.exp(eps) * 1.1, (z, ratio)


def test_rational_at_least_never_rounds_down() -> None:
    for x in [0.1, 1 / 3, math.pi, 1e-7, 12345.6789]:
        r = rational_at_least(x)
        assert r >= Fraction(x) and float(r) - x < 2e-6


@pytest.mark.parametrize(
    ("func", "arg"),
    [(bernoulli_exp, Fraction(-1)), (discrete_laplace, Fraction(0)), (discrete_gaussian, Fraction(-2))],
)
def test_sampler_argument_validation(func: object, arg: Fraction) -> None:
    with pytest.raises(ValueError):
        func(arg, random.Random(0))  # type: ignore[operator]
