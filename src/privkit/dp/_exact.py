"""Exact samplers for the discrete Laplace and discrete Gaussian distributions.

Implements Algorithms 1-3 of Canonne, Kamath & Steinke, "The Discrete Gaussian
for Differential Privacy" (NeurIPS 2020). All arithmetic is on Python integers
and :class:`fractions.Fraction`, so sampling is exact: there is no floating-point
rounding that could leak information the way naive Laplace sampling can
(Mironov, CCS 2012).

Expected running time is O(1) Bernoulli trials per sample for the discrete
Laplace and O(1) discrete-Laplace draws per discrete-Gaussian sample (the
rejection rate is bounded by a constant for sigma >= 1).
"""

from __future__ import annotations

import math
import random
from fractions import Fraction

_ONE = Fraction(1)


def bernoulli(p: Fraction, rng: random.Random) -> bool:
    """Exact Bernoulli(p) for rational p in [0, 1]."""
    return rng.randrange(p.denominator) < p.numerator


def _bernoulli_exp_le1(gamma: Fraction, rng: random.Random) -> bool:
    k = 1
    while bernoulli(gamma / k, rng):
        k += 1
    return k % 2 == 1


def bernoulli_exp(gamma: Fraction, rng: random.Random) -> bool:
    """Exact Bernoulli(exp(-gamma)) for rational gamma >= 0 (CKS20 Algorithm 1)."""
    if gamma < 0:
        raise ValueError("gamma must be non-negative")
    while gamma > 1:
        if not _bernoulli_exp_le1(_ONE, rng):
            return False
        gamma -= 1
    return _bernoulli_exp_le1(gamma, rng)


def discrete_laplace(scale: Fraction, rng: random.Random) -> int:
    """Sample Z with P[Z = z] proportional to exp(-|z| / scale) (CKS20 Algorithm 2)."""
    if scale <= 0:
        raise ValueError("scale must be positive")
    t, s = scale.numerator, scale.denominator  # scale = t / s
    while True:
        u = rng.randrange(t)
        if not bernoulli_exp(Fraction(u, t), rng):
            continue
        v = 0
        while bernoulli_exp(_ONE, rng):
            v += 1
        y = (u + t * v) // s
        negative = rng.randrange(2) == 1
        if negative and y == 0:
            continue
        return -y if negative else y


def discrete_gaussian(sigma2: Fraction, rng: random.Random) -> int:
    """Sample Z with P[Z = z] proportional to exp(-z^2 / (2 sigma^2)) (CKS20 Algorithm 3)."""
    if sigma2 <= 0:
        raise ValueError("sigma^2 must be positive")
    t = math.isqrt(sigma2.numerator // sigma2.denominator) + 1
    while True:
        y = discrete_laplace(Fraction(t), rng)
        gamma = (abs(y) - sigma2 / t) ** 2 / (2 * sigma2)
        if bernoulli_exp(gamma, rng):
            return y


def rational_at_least(x: float, max_denominator: int = 10**6) -> Fraction:
    """A rational approximation of ``x`` that is never smaller than ``x``.

    Rounding noise parameters *up* keeps the privacy guarantee intact.
    """
    approx = Fraction(x).limit_denominator(max_denominator)
    if approx < Fraction(x):
        approx += Fraction(1, max_denominator)
    return approx
