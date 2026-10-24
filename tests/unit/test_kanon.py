from __future__ import annotations

import itertools
import random
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from privkit.errors import ConfigurationError, InvalidInputError
from privkit.kanon import (
    Hierarchy,
    IntervalHierarchy,
    MappingHierarchy,
    MaskingHierarchy,
    SuppressionHierarchy,
    assess,
    equivalence_classes,
    generalize_to_k,
    mondrian,
    parse_hierarchy,
)
from privkit.kanon.metrics import ordered_emd, total_variation

TABLE = [
    {"age": "34", "zip": "02139", "sex": "F", "dx": "flu", "income": "50"},
    {"age": "34", "zip": "02139", "sex": "F", "dx": "cold", "income": "60"},
    {"age": "36", "zip": "02138", "sex": "M", "dx": "flu", "income": "70"},
    {"age": "37", "zip": "02138", "sex": "M", "dx": "flu", "income": "80"},
    {"age": "52", "zip": "02141", "sex": "F", "dx": "hiv", "income": "90"},
]


def synthetic(n: int, seed: int = 1) -> list[dict[str, str]]:
    r = random.Random(seed)
    return [
        {
            "age": str(r.randint(18, 90)),
            "zip": f"0213{r.randint(0, 9)}",
            "sex": r.choice("MF"),
            "dx": r.choice(["flu", "cold", "hiv", "asthma"]),
        }
        for _ in range(n)
    ]


def test_assess_counts_classes_and_risk() -> None:
    rep = assess(TABLE, ["age", "zip", "sex"], sensitive=["dx"], k=2)
    assert rep.n_classes == 4 and rep.k == 1 and not rep.satisfies_k
    assert rep.violating_classes == 3 and rep.records_at_risk == 3 and rep.unique_records == 3
    assert rep.prosecutor_risk_max == 1.0 and rep.prosecutor_risk_avg == pytest.approx(0.8)
    [dx] = rep.sensitive
    assert dx.distinct_l == 1 and not dx.numeric
    assert rep.to_dict()["satisfies_k"] is False and "smallest_classes" not in rep.to_dict()
    assert rep.to_dict(include_class_keys=True)["smallest_classes"]


def test_l_diversity_and_t_closeness_on_known_table() -> None:
    rows = [{"q": "a", "s": "x"}, {"q": "a", "s": "y"}, {"q": "b", "s": "x"}, {"q": "b", "s": "x"}]
    [s] = assess(rows, ["q"], sensitive=["s"], k=2).sensitive
    assert s.distinct_l == 1 and s.entropy_l == pytest.approx(1.0)
    # global: x=.75,y=.25 ; class b: x=1 -> TV .25 ; class a: .5/.5 -> TV .25
    assert s.t_closeness == pytest.approx(0.25)


def test_numeric_sensitive_uses_ordered_emd() -> None:
    [inc] = assess(TABLE, ["sex"], sensitive=["income"]).sensitive
    assert inc.numeric and 0 < inc.t_closeness <= 1
    assert ordered_emd({"1": 1.0}, {"3": 1.0}, ["1", "2", "3"]) == pytest.approx(1.0)
    assert ordered_emd({"1": 1.0}, {"2": 1.0}, ["1", "2", "3"]) == pytest.approx(0.5)
    assert ordered_emd({"1": 1.0}, {"1": 1.0}, ["1"]) == 0.0
    assert total_variation({"a": 1.0}, {"b": 1.0}) == 1.0


def test_assess_edge_cases() -> None:
    assert assess([], ["a"]).n_records == 0
    with pytest.raises(InvalidInputError):
        assess(TABLE, [])
    with pytest.raises(InvalidInputError):
        assess(TABLE, ["nope"])
    with pytest.raises(InvalidInputError):
        assess(TABLE, ["age"], sensitive=["nope"])
    with pytest.raises(InvalidInputError):
        assess(TABLE, ["age"], k=0)
    assert assess(TABLE, ["sex"]).satisfies_k  # no target -> trivially satisfied
    assert len(equivalence_classes(TABLE, ["sex"])) == 2


def test_hierarchies() -> None:
    age = IntervalHierarchy((5, 10))
    assert [age.generalize("37", lvl) for lvl in range(4)] == ["37", "[35-40)", "[30-40)", "*"]
    assert age.generalize("n/a", 1) == "*" and IntervalHierarchy((0.5,)).generalize("1.2", 1) == "[1-1.5)"
    zipc = MaskingHierarchy(2)
    assert [zipc.generalize("02139", lvl) for lvl in range(4)] == ["02139", "0213*", "021**", "*"]
    assert zipc.generalize("1", 2) == "*"
    tax = MappingHierarchy([{"flu": "respiratory", "cold": "respiratory"}, {"respiratory": "illness"}])
    assert [tax.generalize("flu", lvl) for lvl in range(4)] == ["flu", "respiratory", "illness", "*"]
    assert tax.generalize("unknown", 1) == "*"
    sup = SuppressionHierarchy()
    assert sup.generalize("F", 0) == "F" and sup.generalize("F", 1) == "*"
    with pytest.raises(InvalidInputError):
        age.generalize("1", 9)
    bad_builders: list[Callable[[], object]] = [
        lambda: IntervalHierarchy(()),
        lambda: IntervalHierarchy((10, 5)),
        lambda: MaskingHierarchy(0),
        lambda: MappingHierarchy([]),
    ]
    for bad in bad_builders:
        with pytest.raises(ConfigurationError):
            bad()


def test_parse_hierarchy() -> None:
    assert isinstance(parse_hierarchy("interval:5,10"), IntervalHierarchy)
    assert parse_hierarchy("mask:3").height == 4
    assert isinstance(parse_hierarchy("suppress"), SuppressionHierarchy)
    for bad in ["interval:x", "nope:1", "mask:"]:
        with pytest.raises(ConfigurationError):
            parse_hierarchy(bad)


def test_generalize_reaches_k_with_minimal_loss() -> None:
    rows = synthetic(1000)
    hier: dict[str, Hierarchy] = {
        "age": IntervalHierarchy((5, 10, 20)),
        "zip": MaskingHierarchy(3),
        "sex": SuppressionHierarchy(),
    }
    res = generalize_to_k(rows, hier, 5, max_suppression=0.02)
    after = assess(res.rows, list(hier), k=5)
    assert after.satisfies_k and res.suppressed <= 20 and len(res.rows) == 1000 - res.suppressed
    assert res.to_dict()["levels"] == res.levels


def test_generalize_minimality_bruteforce_small() -> None:
    rows = synthetic(60, seed=3)
    hier: dict[str, Hierarchy] = {"age": IntervalHierarchy((10, 30)), "sex": SuppressionHierarchy()}
    res = generalize_to_k(rows, hier, 3)
    feasible_losses = []
    for a, s in itertools.product(range(4), range(2)):
        gen = [{"age": hier["age"].generalize(r["age"], a), "sex": hier["sex"].generalize(r["sex"], s)} for r in rows]
        if assess(gen, ["age", "sex"], k=3).satisfies_k:
            feasible_losses.append((a / 3 + s / 1) / 2)
    assert res.precision_loss == pytest.approx(min(feasible_losses))


def test_generalize_errors() -> None:
    with pytest.raises(InvalidInputError):
        generalize_to_k(TABLE, {"sex": SuppressionHierarchy()}, 10)
    with pytest.raises(InvalidInputError):
        generalize_to_k(TABLE, {"sex": SuppressionHierarchy()}, 0)
    with pytest.raises(ConfigurationError):
        generalize_to_k(TABLE, {"sex": SuppressionHierarchy()}, 2, max_suppression=1.0)
    with pytest.raises(ConfigurationError):
        generalize_to_k(TABLE, {}, 2)
    with pytest.raises(InvalidInputError):
        generalize_to_k(TABLE, {"nope": SuppressionHierarchy()}, 2)


def test_mondrian_produces_k_anonymous_output() -> None:
    rows = synthetic(1000)
    res = mondrian(rows, ["age", "zip", "sex"], 5, categorical=["zip"])
    rep = assess(res.rows, ["age", "zip", "sex"], k=5)
    assert rep.satisfies_k and len(res.rows) == 1000
    assert res.n_partitions == rep.n_classes and res.n_partitions > 50
    assert 0 <= res.ncp < 0.5 and res.discernibility >= 1000 * 5
    assert all(r["zip"].startswith("0213") for r in res.rows)
    assert res.to_dict()["n_output_rows"] == 1000


def test_mondrian_numeric_range_keeps_original_format() -> None:
    rows = [{"zip": z} for z in ["02138", "02139", "02140", "02141"]]
    res = mondrian(rows, ["zip"], 2)
    assert {r["zip"] for r in res.rows} == {"[02138-02139]", "[02140-02141]"}


@settings(max_examples=25, deadline=None)
@given(n=st.integers(5, 120), k=st.integers(1, 5), seed=st.integers(0, 10_000))
def test_mondrian_property(n: int, k: int, seed: int) -> None:
    rows = synthetic(n, seed)
    res = mondrian(rows, ["age", "sex"], k)
    assert assess(res.rows, ["age", "sex"], k=k).satisfies_k
    assert sorted(r["dx"] for r in res.rows) == sorted(r["dx"] for r in rows)


def test_mondrian_errors() -> None:
    with pytest.raises(InvalidInputError):
        mondrian(TABLE, ["age"], 0)
    with pytest.raises(InvalidInputError):
        mondrian(TABLE, [], 2)
    with pytest.raises(InvalidInputError):
        mondrian(TABLE, ["age"], 6)
    with pytest.raises(InvalidInputError):
        mondrian(TABLE, ["nope"], 2)
