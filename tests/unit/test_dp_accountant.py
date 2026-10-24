from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from privkit.dp import (
    Charge,
    Composition,
    GaussianMechanism,
    LaplaceMechanism,
    PrivacyAccountant,
    PrivacyCost,
    charge_for,
)
from privkit.errors import BudgetExceededError, ConfigurationError


def lap(eps: float) -> Charge:
    return charge_for(LaplaceMechanism(eps), f"lap{eps}")


def test_basic_composition_and_exhaustion() -> None:
    acct = PrivacyAccountant(1.0)
    acct.charge(lap(0.4))
    acct.charge(lap(0.6))
    assert acct.spent().epsilon == pytest.approx(1.0)
    assert acct.remaining().epsilon == pytest.approx(0.0)
    with pytest.raises(BudgetExceededError):
        acct.charge(lap(0.01))
    assert len(acct.ledger) == 2  # the refused charge was not recorded


def test_multi_charge_is_atomic() -> None:
    acct = PrivacyAccountant(1.0)
    with pytest.raises(BudgetExceededError):
        acct.charge(lap(0.6), lap(0.6))
    assert acct.ledger == ()
    assert acct.can_afford([lap(0.5), lap(0.5)]) and not acct.can_afford([lap(1.1)])
    assert acct.preview([lap(0.3)]).epsilon == pytest.approx(0.3)


def test_delta_budget_enforced() -> None:
    acct = PrivacyAccountant(10.0, 1e-6)
    g = charge_for(GaussianMechanism(0.5, 1e-6))
    acct.charge(g)
    with pytest.raises(BudgetExceededError):
        acct.charge(charge_for(GaussianMechanism(0.5, 1e-7)))


def test_advanced_composition_beats_basic_for_many_small_releases() -> None:
    basic = PrivacyAccountant(100.0, 1e-5)
    adv = PrivacyAccountant(100.0, 1e-5, Composition.ADVANCED)
    for _ in range(200):
        basic.charge(lap(0.05))
        adv.charge(lap(0.05))
    assert basic.spent().epsilon == pytest.approx(10.0)
    assert adv.spent().epsilon < 6.0 and adv.spent().delta == pytest.approx(1e-5)


def test_advanced_falls_back_to_basic_when_better() -> None:
    adv = PrivacyAccountant(10.0, 1e-5, Composition.ADVANCED)
    adv.charge(lap(1.0))
    assert adv.spent() == PrivacyCost(1.0, 0.0)


def test_rdp_composition_of_gaussians() -> None:
    rdp = PrivacyAccountant(50.0, 1e-5, "rdp")
    basic = PrivacyAccountant(50.0, 1.0 - 1e-9)
    for _ in range(50):
        c = charge_for(GaussianMechanism(0.5, 1e-7))
        rdp.charge(c)
        basic.charge(c)
    assert rdp.spent().epsilon < basic.spent().epsilon / 3
    assert rdp.spent().delta == pytest.approx(1e-5)


def test_rdp_mixes_curve_and_curveless_charges() -> None:
    acct = PrivacyAccountant(5.0, 1e-5, Composition.RDP)
    acct.charge(charge_for(GaussianMechanism(0.5, 1e-6)))
    acct.charge(Charge("selection", "laplace_threshold", PrivacyCost(0.2, 5e-6)))
    spent = acct.spent()
    assert spent.delta <= 1e-5 + 1e-15 and spent.epsilon > 0.2


def test_non_basic_needs_delta() -> None:
    with pytest.raises(ConfigurationError):
        PrivacyAccountant(1.0, 0.0, Composition.RDP)


def test_persistence_roundtrip(tmp_path: Path) -> None:
    acct = PrivacyAccountant(2.0, 1e-5, "rdp")
    acct.charge(lap(0.5), Charge("sel", "laplace_threshold", PrivacyCost(0.1, 1e-6)))
    path = tmp_path / "ledger.json"
    acct.save(path)
    loaded = PrivacyAccountant.load(path)
    assert loaded.ledger == acct.ledger and loaded.composition is Composition.RDP
    assert loaded.spent() == acct.spent()
    assert json.loads(path.read_text())["budget"]["epsilon"] == 2.0


@pytest.mark.parametrize(
    "content",
    ["not json", "[]", '{"budget": 3}', '{"budget": {"epsilon": 1}, "charges": [{"label": "x", "mechanism": "m", "epsilon": "a", "delta": 0}]}'],
)
def test_malformed_ledgers(tmp_path: Path, content: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(ConfigurationError):
        PrivacyAccountant.load(path)


def test_missing_ledger_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        PrivacyAccountant.load(tmp_path / "absent.json")


def test_concurrent_charges_never_overspend() -> None:
    acct = PrivacyAccountant(1.0)
    errors: list[Exception] = []

    def worker() -> None:
        for _ in range(50):
            try:
                acct.charge(lap(0.01))
            except BudgetExceededError as exc:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(acct.ledger) == 100 and len(errors) == 300
    assert acct.spent().epsilon == pytest.approx(1.0)
