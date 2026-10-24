"""Privacy-budget accounting with sequential composition.

A :class:`PrivacyAccountant` holds a total budget (epsilon, delta) and a ledger
of charges. A release is allowed only if the *composed* cost of everything
charged so far plus the new release stays within budget; otherwise
:class:`BudgetExceededError` is raised and nothing is recorded.

Three composition rules are available; the accountant always reports the
smallest epsilon among the rules that are valid for the chosen mode:

* ``basic`` - epsilons and deltas add up (always valid, also for adaptively
  chosen parameters).
* ``advanced`` - heterogeneous advanced composition, spending a slack delta.
* ``rdp`` - Renyi-DP composition of each mechanism's RDP curve, converted to
  (epsilon, delta) at the remaining delta. Charges without an RDP curve
  (for example partition selection) are composed on top with the basic rule.

The advanced and RDP bounds assume the sequence of mechanisms and their
parameters is fixed in advance (or at least not chosen from earlier noisy
outputs); see ``docs/DP_GUARANTEES.md``.
"""

from __future__ import annotations

import json
import logging
import math
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from privkit.dp import accounting_math as am
from privkit.dp.mechanisms import Mechanism, PrivacyCost
from privkit.errors import BudgetExceededError, ConfigurationError

logger = logging.getLogger(__name__)

_EPS_TOL = 1e-9
_DELTA_TOL = 1e-15


class Composition(StrEnum):
    BASIC = "basic"
    ADVANCED = "advanced"
    RDP = "rdp"


@dataclass(frozen=True)
class Charge:
    label: str
    mechanism: str
    cost: PrivacyCost
    rdp: tuple[float, ...] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "mechanism": self.mechanism,
            "epsilon": self.cost.epsilon,
            "delta": self.cost.delta,
            "rdp": list(self.rdp) if self.rdp is not None else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Charge:
        rdp = data.get("rdp")
        eps, delta = data["epsilon"], data["delta"]
        if not isinstance(eps, int | float) or not isinstance(delta, int | float):
            raise ConfigurationError("ledger entry has non-numeric epsilon/delta")
        return cls(
            label=str(data["label"]),
            mechanism=str(data["mechanism"]),
            cost=PrivacyCost(float(eps), float(delta)),
            rdp=tuple(float(x) for x in rdp) if isinstance(rdp, list) else None,
        )


def charge_for(mechanism: Mechanism, label: str = "") -> Charge:
    """Build a ledger charge (with RDP curve) for a mechanism release."""
    return Charge(label or mechanism.name, mechanism.name, mechanism.cost, mechanism.rdp_curve())


class PrivacyAccountant:
    """Tracks spending against an (epsilon, delta) budget. Thread-safe."""

    def __init__(
        self,
        epsilon: float,
        delta: float = 0.0,
        composition: Composition | str = Composition.BASIC,
        *,
        charges: Sequence[Charge] = (),
    ) -> None:
        self.budget = PrivacyCost(epsilon, delta)
        self.composition = Composition(composition)
        if self.composition is not Composition.BASIC and delta <= 0:
            raise ConfigurationError(f"{self.composition.value} composition needs a positive delta budget")
        self._charges: list[Charge] = list(charges)
        self._lock = threading.Lock()

    # -- composition -------------------------------------------------------
    def _compose(self, charges: Sequence[Charge]) -> PrivacyCost:
        if not charges:
            return PrivacyCost(0.0, 0.0)
        basic_eps = math.fsum(c.cost.epsilon for c in charges)
        basic_delta = math.fsum(c.cost.delta for c in charges)
        candidates: list[tuple[float, float]] = [(basic_eps, basic_delta)]
        budget_delta = self.budget.delta
        if self.composition is Composition.ADVANCED:
            slack = budget_delta - basic_delta
            if slack > 0:
                adv = am.advanced_composition([c.cost.epsilon for c in charges], slack)
                candidates.append((adv, budget_delta))
        elif self.composition is Composition.RDP:
            with_curve = [c for c in charges if c.rdp is not None]
            without = [c for c in charges if c.rdp is None]
            extra_delta = math.fsum(c.cost.delta for c in without)
            conv_delta = budget_delta - extra_delta
            if with_curve and conv_delta > 0:
                total = [math.fsum(vals) for vals in zip(*(c.rdp for c in with_curve if c.rdp), strict=True)]
                eps = am.rdp_to_dp(total, am.RDP_ORDERS, conv_delta)
                eps += math.fsum(c.cost.epsilon for c in without)
                candidates.append((eps, budget_delta))
        within = [c for c in candidates if c[1] <= budget_delta + _DELTA_TOL]
        eps, delta = min(within or candidates, key=lambda c: c[0])
        return PrivacyCost(eps, min(delta, 1 - 1e-15))

    @property
    def ledger(self) -> tuple[Charge, ...]:
        with self._lock:
            return tuple(self._charges)

    def spent(self) -> PrivacyCost:
        with self._lock:
            return self._compose(self._charges)

    def remaining(self) -> PrivacyCost:
        s = self.spent()
        return PrivacyCost(max(self.budget.epsilon - s.epsilon, 0.0), max(self.budget.delta - s.delta, 0.0))

    def _fits(self, cost: PrivacyCost) -> bool:
        return cost.epsilon <= self.budget.epsilon + _EPS_TOL and cost.delta <= self.budget.delta + _DELTA_TOL

    def preview(self, new: Sequence[Charge]) -> PrivacyCost:
        """Composed cost if ``new`` were charged (nothing is recorded)."""
        with self._lock:
            return self._compose([*self._charges, *new])

    def can_afford(self, new: Sequence[Charge]) -> bool:
        return self._fits(self.preview(new))

    def charge(self, *new: Charge) -> PrivacyCost:
        """Atomically record ``new`` charges, or raise :class:`BudgetExceededError` and record nothing."""
        with self._lock:
            after = self._compose([*self._charges, *new])
            if not self._fits(after):
                raise BudgetExceededError(
                    f"release would raise spending to (eps={after.epsilon:.4g}, delta={after.delta:.3g}) "
                    f"over the budget (eps={self.budget.epsilon:.4g}, delta={self.budget.delta:.3g})"
                )
            self._charges.extend(new)
        logger.info("charged %s: total eps=%.4g delta=%.3g", ",".join(c.label for c in new), after.epsilon, after.delta)
        return after

    # -- persistence ---------------------------------------------------------
    def to_dict(self) -> dict[str, object]:
        spent = self.spent()
        return {
            "budget": {"epsilon": self.budget.epsilon, "delta": self.budget.delta},
            "composition": self.composition.value,
            "spent": {"epsilon": spent.epsilon, "delta": spent.delta},
            "charges": [c.to_dict() for c in self.ledger],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> PrivacyAccountant:
        budget = data.get("budget")
        charges = data.get("charges", [])
        if not isinstance(budget, dict) or not isinstance(charges, list):
            raise ConfigurationError("malformed accountant state")
        try:
            return cls(
                float(budget["epsilon"]),
                float(budget.get("delta", 0.0)),
                str(data.get("composition", "basic")),
                charges=[Charge.from_dict(c) for c in charges],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(f"malformed accountant state: {exc!r}") from None

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        tmp.replace(path)  # atomic on POSIX

    @classmethod
    def load(cls, path: Path) -> PrivacyAccountant:
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"cannot read privacy ledger {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigurationError("malformed accountant state")
        return cls.from_dict(data)
