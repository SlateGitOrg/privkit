from __future__ import annotations

import logging
import math
import random

import pytest

from privkit.dp import (
    DiscreteGaussianMechanism,
    DiscreteLaplaceMechanism,
    GaussianMechanism,
    LaplaceMechanism,
    PrivacyCost,
    insecure_seeded_rng,
    secure_rng,
)
from privkit.dp import accounting_math as am
from privkit.errors import ConfigurationError


def test_privacy_cost_validation_and_add() -> None:
    assert PrivacyCost(1, 1e-6) + PrivacyCost(0.5) == PrivacyCost(1.5, 1e-6)
    for bad in [(-1, 0), (math.inf, 0), (1, 1), (1, -0.1)]:
        with pytest.raises(ConfigurationError):
            PrivacyCost(*bad)


def test_analytic_gaussian_is_tight_and_beats_classic() -> None:
    for eps, delta in [(0.1, 1e-5), (0.5, 1e-6), (0.9, 1e-3)]:
        analytic = am.analytic_gaussian_sigma(eps, delta, 1.0)
        assert am.gaussian_delta(analytic, eps, 1.0) <= delta
        assert am.gaussian_delta(analytic * 0.99, eps, 1.0) > delta  # tight: 1% less noise breaks it
        assert analytic < am.classic_gaussian_sigma(eps, delta, 1.0)
    # Known value from Balle & Wang (2018): eps=1, delta=1e-5 -> sigma ~ 3.73
    assert am.analytic_gaussian_sigma(1.0, 1e-5, 1.0) == pytest.approx(3.7306, abs=1e-3)
    # Works for large epsilon where the classic formula is invalid
    assert am.analytic_gaussian_sigma(8.0, 1e-6, 1.0) < 1.0


def test_gaussian_delta_extreme_tail() -> None:
    assert am.gaussian_delta(0.01, 50.0, 1.0) >= 0.0
    assert am._log_phi(-40.0) == pytest.approx(math.log(1e-300), rel=1) or am._log_phi(-40.0) < -700


def test_laplace_rdp_properties() -> None:
    eps = 1.0
    curve = [am.laplace_rdp(eps, a) for a in am.RDP_ORDERS]
    assert all(x <= y + 1e-12 for x, y in zip(curve, curve[1:], strict=False))  # non-decreasing in alpha
    assert curve[-1] == pytest.approx(eps, rel=1e-2)  # tends to eps as alpha -> inf
    assert all(c <= eps + 1e-12 for c in curve)
    assert am.pure_dp_rdp(1.0, 2.0) == 1.0 and am.pure_dp_rdp(0.1, 2.0) == pytest.approx(0.01)


def test_rdp_conversion_is_a_valid_upper_bound_for_gaussian() -> None:
    mech = GaussianMechanism(1.0, 1e-5)
    eps_rdp = am.rdp_to_dp(mech.rdp_curve(), am.RDP_ORDERS, 1e-5)
    assert 1.0 <= eps_rdp < 1.5
    with pytest.raises(ValueError):
        am.rdp_to_dp([1.0], [2.0], 0.0)


def test_advanced_and_zcdp_math() -> None:
    k_eps = [0.1] * 100
    assert am.advanced_composition(k_eps, 1e-6) < sum(k_eps)
    assert am.zcdp_to_dp(0.5, 1e-5) == pytest.approx(0.5 + 2 * math.sqrt(0.5 * math.log(1e5)))


def test_mechanism_metadata() -> None:
    lap = LaplaceMechanism(0.5, 2.0, rng=random.Random(1))
    assert lap.scale == 4.0 and lap.cost == PrivacyCost(0.5) and lap.std == pytest.approx(4 * math.sqrt(2))
    assert lap.ci_halfwidth(0.95) == pytest.approx(4 * math.log(20))
    assert isinstance(lap.release(10.0), float)
    dl = DiscreteLaplaceMechanism(0.5, 2, rng=random.Random(1))
    assert isinstance(dl.noise(), int) and dl.scale == pytest.approx(4.0)
    assert dl.rdp(2.0) == pytest.approx(0.25)
    g = GaussianMechanism(0.5, 1e-6, 1.0, calibration="classic", rng=random.Random(1))
    assert g.calibration == "classic" and g.rdp(2.0) == pytest.approx(2 / (2 * g.sigma**2))
    dg = DiscreteGaussianMechanism(1.0, 1e-6, 1, rng=random.Random(1))
    assert dg.epsilon <= 1.0 + 1e-9 and dg.rho == pytest.approx(1 / (2 * dg.sigma**2))
    assert dg.cost.delta == 1e-6 and dg.rdp(3.0) == pytest.approx(3 * dg.rho)
    assert isinstance(dg.release(5), int | float) and dg.std == dg.sigma
    dg2 = DiscreteGaussianMechanism(sigma=3.0, delta=1e-6)
    assert dg2.sigma == pytest.approx(3.0) and dg2.ci_halfwidth() == math.ceil(3.0 * 1.959963984540054)


@pytest.mark.parametrize(
    "build",
    [
        lambda: LaplaceMechanism(0.0),
        lambda: LaplaceMechanism(1.0, -1.0),
        lambda: DiscreteLaplaceMechanism(1.0, 0),
        lambda: DiscreteLaplaceMechanism(1.0, 1.5),  # type: ignore[arg-type]
        lambda: GaussianMechanism(1.0, 0.0),
        lambda: GaussianMechanism(1.5, 1e-5, calibration="classic"),
        lambda: GaussianMechanism(0.5, 1e-5, calibration="magic"),
        lambda: DiscreteGaussianMechanism(1.0, None),
        lambda: DiscreteGaussianMechanism(sigma=2.0),
        lambda: DiscreteGaussianMechanism(1.0, 1.5),
        lambda: DiscreteGaussianMechanism(1.0, 1e-5, 0),
        lambda: DiscreteGaussianMechanism(sigma=-1.0, delta=1e-5),
    ],
)
def test_mechanism_validation(build: object) -> None:
    with pytest.raises(ConfigurationError):
        build()  # type: ignore[operator]


def test_rng_helpers(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    r = insecure_seeded_rng(5)
    assert r.random() == random.Random(5).random()
    assert "NO privacy" in caplog.text
    assert secure_rng().random() != secure_rng().random()
