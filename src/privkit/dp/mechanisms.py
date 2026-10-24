"""Noise-adding mechanisms.

=========================  =========  ==================  =============================
mechanism                  output     guarantee           sampler
=========================  =========  ==================  =============================
LaplaceMechanism           float      epsilon-DP          continuous (float)
DiscreteLaplaceMechanism   int        epsilon-DP          exact (CKS20 Algorithm 2)
GaussianMechanism          float      (epsilon, delta)    continuous, analytic calibration
DiscreteGaussianMechanism  int        rho-zCDP            exact (CKS20 Algorithm 3)
=========================  =========  ==================  =============================

Every mechanism reports its :class:`PrivacyCost`, its Renyi-DP curve (used by the
RDP accountant), its noise standard deviation and a confidence half-width.
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from statistics import NormalDist

from privkit.dp import accounting_math as am
from privkit.dp._exact import discrete_gaussian, discrete_laplace, rational_at_least
from privkit.dp.rng import secure_rng
from privkit.errors import ConfigurationError


@dataclass(frozen=True)
class PrivacyCost:
    """An (epsilon, delta) privacy cost; delta = 0 means pure DP."""

    epsilon: float
    delta: float = 0.0

    def __post_init__(self) -> None:
        if not (math.isfinite(self.epsilon) and self.epsilon >= 0):
            raise ConfigurationError("epsilon must be a finite non-negative number")
        if not 0 <= self.delta < 1:
            raise ConfigurationError("delta must be in [0, 1)")

    def __add__(self, other: PrivacyCost) -> PrivacyCost:
        return PrivacyCost(self.epsilon + other.epsilon, min(self.delta + other.delta, 1 - 1e-15))


def _check_positive(name: str, value: float) -> None:
    if not (math.isfinite(value) and value > 0):
        raise ConfigurationError(f"{name} must be a finite positive number")


class Mechanism(ABC):
    """Base class: ``release(value)`` returns ``value`` plus calibrated noise."""

    name: str

    def __init__(self, rng: random.Random | None = None) -> None:
        self.rng = rng if rng is not None else secure_rng()

    @property
    @abstractmethod
    def cost(self) -> PrivacyCost: ...

    @abstractmethod
    def rdp(self, order: float) -> float:
        """Renyi-DP epsilon at order ``order`` (> 1)."""

    @property
    @abstractmethod
    def std(self) -> float:
        """Standard deviation of the added noise."""

    @abstractmethod
    def ci_halfwidth(self, confidence: float = 0.95) -> float:
        """Half-width w with P(|noise| <= w) >= confidence."""

    @abstractmethod
    def noise(self) -> float | int: ...

    def release(self, value: float) -> float:
        return value + self.noise()

    def rdp_curve(self, orders: tuple[float, ...] = am.RDP_ORDERS) -> tuple[float, ...]:
        return tuple(self.rdp(a) for a in orders)


class LaplaceMechanism(Mechanism):
    """Laplace(0, b) noise with b = sensitivity / epsilon (L1 sensitivity)."""

    name = "laplace"

    def __init__(self, epsilon: float, sensitivity: float = 1.0, rng: random.Random | None = None) -> None:
        _check_positive("epsilon", epsilon)
        _check_positive("sensitivity", sensitivity)
        super().__init__(rng)
        self.epsilon = epsilon
        self.sensitivity = sensitivity
        self.scale = sensitivity / epsilon

    @property
    def cost(self) -> PrivacyCost:
        return PrivacyCost(self.epsilon)

    def rdp(self, order: float) -> float:
        return am.laplace_rdp(self.epsilon, order)

    @property
    def std(self) -> float:
        return math.sqrt(2) * self.scale

    def ci_halfwidth(self, confidence: float = 0.95) -> float:
        return self.scale * math.log(1 / (1 - confidence))

    def noise(self) -> float:
        # Difference of two i.i.d. Exp(1) variables is Laplace(0, 1).
        return self.scale * (self.rng.expovariate(1.0) - self.rng.expovariate(1.0))


class DiscreteLaplaceMechanism(Mechanism):
    """Integer noise P[Z=z] ~ exp(-|z| * epsilon / sensitivity); exact sampler, epsilon-DP."""

    name = "discrete_laplace"

    def __init__(self, epsilon: float, sensitivity: int = 1, rng: random.Random | None = None) -> None:
        _check_positive("epsilon", epsilon)
        if not isinstance(sensitivity, int) or sensitivity < 1:
            raise ConfigurationError("discrete mechanisms need a positive integer sensitivity")
        super().__init__(rng)
        self.epsilon = epsilon
        self.sensitivity = sensitivity
        # scale t = sensitivity / epsilon, rounded *up* to a rational (more noise, never less)
        self._scale = rational_at_least(sensitivity / epsilon)
        self.scale = float(self._scale)

    @property
    def cost(self) -> PrivacyCost:
        return PrivacyCost(self.epsilon)

    def rdp(self, order: float) -> float:
        return am.pure_dp_rdp(self.epsilon, order)

    @property
    def std(self) -> float:
        q = math.exp(-1 / self.scale)
        return math.sqrt(2 * q) / (1 - q)

    def ci_halfwidth(self, confidence: float = 0.95) -> float:
        # P(|Z| >= k) = 2 q^k / (1 + q) for k >= 1
        q = math.exp(-1 / self.scale)
        k = math.log((1 - confidence) * (1 + q) / 2) / math.log(q)
        return float(max(math.ceil(k) - 1, 0))

    def noise(self) -> int:
        return discrete_laplace(self._scale, self.rng)


class GaussianMechanism(Mechanism):
    """Gaussian noise calibrated to (epsilon, delta) for L2 sensitivity.

    ``calibration="analytic"`` (default) solves the exact privacy profile of the
    Gaussian mechanism (Balle & Wang 2018) and is valid for any epsilon > 0;
    ``"classic"`` uses the textbook formula, valid only for epsilon < 1.
    """

    name = "gaussian"

    def __init__(
        self,
        epsilon: float,
        delta: float,
        sensitivity: float = 1.0,
        *,
        calibration: str = "analytic",
        rng: random.Random | None = None,
    ) -> None:
        _check_positive("epsilon", epsilon)
        _check_positive("sensitivity", sensitivity)
        if not 0 < delta < 1:
            raise ConfigurationError("the Gaussian mechanism needs delta in (0, 1)")
        super().__init__(rng)
        self.epsilon, self.delta, self.sensitivity = epsilon, delta, sensitivity
        if calibration == "analytic":
            self.sigma = am.analytic_gaussian_sigma(epsilon, delta, sensitivity)
        elif calibration == "classic":
            if epsilon >= 1:
                raise ConfigurationError("classic Gaussian calibration requires epsilon < 1")
            self.sigma = am.classic_gaussian_sigma(epsilon, delta, sensitivity)
        else:
            raise ConfigurationError("calibration must be 'analytic' or 'classic'")
        self.calibration = calibration

    @property
    def cost(self) -> PrivacyCost:
        return PrivacyCost(self.epsilon, self.delta)

    def rdp(self, order: float) -> float:
        return order * self.sensitivity**2 / (2 * self.sigma**2)

    @property
    def std(self) -> float:
        return self.sigma

    def ci_halfwidth(self, confidence: float = 0.95) -> float:
        return self.sigma * NormalDist().inv_cdf(0.5 + confidence / 2)

    def noise(self) -> float:
        return self.rng.normalvariate(0.0, self.sigma)


class DiscreteGaussianMechanism(Mechanism):
    """Integer Gaussian noise (exact sampler), rho-zCDP with rho = sensitivity^2 / (2 sigma^2).

    Construct it either from ``sigma`` directly or from a target ``(epsilon, delta)``;
    in the latter case sigma is the smallest value whose zCDP-to-DP conversion
    meets the target (conservative compared to the analytic continuous bound).
    """

    name = "discrete_gaussian"

    def __init__(
        self,
        epsilon: float | None = None,
        delta: float | None = None,
        sensitivity: int = 1,
        *,
        sigma: float | None = None,
        rng: random.Random | None = None,
    ) -> None:
        if not isinstance(sensitivity, int) or sensitivity < 1:
            raise ConfigurationError("discrete mechanisms need a positive integer sensitivity")
        super().__init__(rng)
        self.sensitivity = sensitivity
        if sigma is not None:
            _check_positive("sigma", sigma)
            if delta is None:
                raise ConfigurationError("delta is required to state the (epsilon, delta) guarantee")
            self.delta = delta
            raw_sigma = sigma
        else:
            if epsilon is None or delta is None:
                raise ConfigurationError("give either sigma (+ delta) or epsilon and delta")
            _check_positive("epsilon", epsilon)
            if not 0 < delta < 1:
                raise ConfigurationError("delta must be in (0, 1)")
            self.delta = delta
            raw_sigma = self._calibrate(epsilon, delta, sensitivity)
        self._sigma2 = rational_at_least(raw_sigma * raw_sigma)
        self.sigma = math.sqrt(float(self._sigma2))
        self.rho = sensitivity**2 / (2 * float(self._sigma2))
        self.epsilon = am.zcdp_to_dp(self.rho, self.delta)

    @staticmethod
    def _calibrate(epsilon: float, delta: float, sensitivity: int) -> float:
        # Find rho with rho + 2 sqrt(rho ln(1/delta)) = epsilon (closed form in sqrt(rho)).
        log_term = math.log(1 / delta)
        root = -math.sqrt(log_term) + math.sqrt(log_term + epsilon)
        rho = root * root
        return sensitivity / math.sqrt(2 * rho)

    @property
    def cost(self) -> PrivacyCost:
        return PrivacyCost(self.epsilon, self.delta)

    def rdp(self, order: float) -> float:
        return order * self.rho

    @property
    def std(self) -> float:
        return self.sigma  # an upper bound; the discrete Gaussian's variance is slightly below sigma^2

    def ci_halfwidth(self, confidence: float = 0.95) -> float:
        return math.ceil(self.sigma * NormalDist().inv_cdf(0.5 + confidence / 2))

    def noise(self) -> int:
        return discrete_gaussian(self._sigma2, self.rng)
