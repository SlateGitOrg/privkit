"""Closed-form privacy calculus: Gaussian calibration, RDP curves, composition bounds."""

from __future__ import annotations

import math
from collections.abc import Sequence
from statistics import NormalDist

_PHI = NormalDist()

# Renyi orders used by the RDP accountant (a standard grid, cf. Opacus / TF-Privacy).
RDP_ORDERS: tuple[float, ...] = (
    1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 6.0, 7.0, 8.0, 10.0, 12.0, 14.0,
    16.0, 20.0, 24.0, 28.0, 32.0, 48.0, 64.0, 96.0, 128.0, 256.0, 512.0, 1024.0,
)  # fmt: skip


def _log_phi(x: float) -> float:
    """log of the standard normal CDF, accurate in the far left tail."""
    if x > -30:
        return math.log(max(_PHI.cdf(x), 1e-300))
    # Mills-ratio asymptotic expansion for very negative x
    return -0.5 * x * x - math.log(-x) - 0.5 * math.log(2 * math.pi)


def gaussian_delta(sigma: float, epsilon: float, sensitivity: float) -> float:
    """Exact delta of the Gaussian mechanism at a given epsilon (Balle & Wang 2018, Thm. 8).

    delta(eps) = Phi(D/(2s) - eps*s/D) - e^eps * Phi(-D/(2s) - eps*s/D)
    """
    a = sensitivity / (2 * sigma)
    b = epsilon * sigma / sensitivity
    first = _PHI.cdf(a - b)
    second = math.exp(epsilon + _log_phi(-a - b))
    return max(first - second, 0.0)


def analytic_gaussian_sigma(epsilon: float, delta: float, sensitivity: float) -> float:
    """Smallest sigma with gaussian_delta(sigma) <= delta, by bisection (analytic Gaussian mechanism)."""
    lo, hi = 1e-12, max(sensitivity, 1.0)
    while gaussian_delta(hi, epsilon, sensitivity) > delta:
        hi *= 2.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if gaussian_delta(mid, epsilon, sensitivity) > delta:
            lo = mid
        else:
            hi = mid
        if hi - lo <= 1e-12 * hi:
            break
    return hi


def classic_gaussian_sigma(epsilon: float, delta: float, sensitivity: float) -> float:
    """sigma = D * sqrt(2 ln(1.25/delta)) / eps (Dwork & Roth Thm. A.1; valid for eps < 1)."""
    return sensitivity * math.sqrt(2 * math.log(1.25 / delta)) / epsilon


def laplace_rdp(epsilon: float, order: float) -> float:
    """RDP of the epsilon-DP Laplace mechanism at order alpha > 1 (Mironov 2017, Prop. 6)."""
    a = order
    log_terms = (
        math.log(a / (2 * a - 1)) + (a - 1) * epsilon,
        math.log((a - 1) / (2 * a - 1)) - a * epsilon,
    )
    m = max(log_terms)
    return (m + math.log(sum(math.exp(t - m) for t in log_terms))) / (a - 1)


def pure_dp_rdp(epsilon: float, order: float) -> float:
    """Generic RDP bound for any epsilon-DP mechanism: min(eps, alpha * eps^2 / 2).

    eps-DP implies (eps^2/2)-zCDP (Bun & Steinke 2016, Prop. 1.4), i.e. RDP alpha*eps^2/2.
    """
    return min(epsilon, order * epsilon * epsilon / 2)


def rdp_to_dp(rdp: Sequence[float], orders: Sequence[float], delta: float) -> float:
    """Convert an RDP curve to (epsilon, delta)-DP.

    Uses the conversion of Canonne, Kamath & Steinke 2020 (Prop. 12) / Asoodeh et al.:
    eps = rdp(a) + log((a-1)/a) - (log(delta) + log(a)) / (a-1), minimized over orders.
    """
    if not 0 < delta < 1:
        raise ValueError("delta must be in (0, 1)")
    best = math.inf
    for r, a in zip(rdp, orders, strict=True):
        eps = r + math.log((a - 1) / a) - (math.log(delta) + math.log(a)) / (a - 1)
        best = min(best, eps)
    return max(best, 0.0)


def zcdp_to_dp(rho: float, delta: float) -> float:
    """rho-zCDP implies (rho + 2 sqrt(rho ln(1/delta)), delta)-DP (Bun & Steinke 2016, Prop. 1.3)."""
    return rho + 2 * math.sqrt(rho * math.log(1 / delta))


def advanced_composition(epsilons: Sequence[float], slack: float) -> float:
    """Heterogeneous advanced composition (Dwork, Rothblum & Vadhan 2010; Kairouz et al. 2015 form).

    eps_total = sqrt(2 ln(1/slack) * sum eps_i^2) + sum eps_i (e^eps_i - 1), with delta_total = sum delta_i + slack.
    """
    sq = sum(e * e for e in epsilons)
    return math.sqrt(2 * math.log(1 / slack) * sq) + sum(e * math.expm1(e) for e in epsilons)
