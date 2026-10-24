"""Micro-benchmarks (single thread, wall clock, median of repeats).

uv run python -u scripts/bench.py [--quick]
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import statistics
import time
from collections.abc import Callable
from fractions import Fraction
from pathlib import Path

from privkit.dp import ContributionBounds, DPAggregator, PrivacyAccountant
from privkit.dp._exact import discrete_gaussian, discrete_laplace
from privkit.evaluation import generate_corpus
from privkit.fpe import DIGITS, Algorithm, FormatPreservingCipher
from privkit.kanon import (
    Hierarchy,
    IntervalHierarchy,
    MaskingHierarchy,
    SuppressionHierarchy,
    generalize_to_k,
    mondrian,
)
from privkit.pii import Detector
from privkit.tokens import Tokenizer


def bench(name: str, unit: str, n: int, fn: Callable[[], object], repeats: int) -> dict[str, object]:
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    med = statistics.median(times)
    row = {"benchmark": name, "n": n, "seconds": round(med, 4), "rate": round(n / med, 1), "unit": unit}
    print(f"{name:<44} {n / med:>14,.0f} {unit}/s   (n={n:,}, median {med:.3f}s of {repeats})")
    return row


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="smaller inputs (used by CI smoke runs)")
    parser.add_argument("--out", default="eval/bench.json")
    args = parser.parse_args()
    scale = 0.1 if args.quick else 1.0
    repeats = 3 if args.quick else 5
    rng = random.Random(1)
    key = bytes(range(32))
    rows = []

    n = int(5000 * scale)
    pans = ["".join(rng.choice("0123456789") for _ in range(16)) for _ in range(n)]

    def encrypt_all(cipher: FormatPreservingCipher, tweak: bytes | None) -> Callable[[], object]:
        return lambda: [cipher.encrypt(p, tweak) for p in pans]

    for alg in (Algorithm.FF1, Algorithm.FF3_1):
        cipher = FormatPreservingCipher(key, DIGITS, alg)
        tweak = None if alg is Algorithm.FF1 else bytes(7)
        rows.append(bench(f"{alg.value} encrypt (16 digits)", "ops", n, encrypt_all(cipher, tweak), repeats))

    tok = Tokenizer(key)
    cards = [f"{p[:4]} {p[4:8]} {p[8:12]} {p[12:]}" for p in pans]
    rows.append(
        bench(
            "tokenize CREDIT_CARD (keep last 4)",
            "ops",
            n,
            lambda: [tok.tokenize(x, "CREDIT_CARD") for x in cards],
            repeats,
        )
    )

    docs = generate_corpus("test", int(2000 * scale), 7)
    det = Detector()
    total_chars = sum(len(d.text) for d in docs)
    rows.append(
        bench(
            "detector analyze (regex+checksum)",
            "chars",
            total_chars,
            lambda: [det.analyze(d.text) for d in docs],
            repeats,
        )
    )

    m = int(20000 * scale)
    rows.append(
        bench(
            "discrete Laplace sample (scale 10)",
            "samples",
            m,
            lambda: [discrete_laplace(Fraction(10), rng) for _ in range(m)],
            repeats,
        )
    )
    rows.append(
        bench(
            "discrete Gaussian sample (sigma^2 25)",
            "samples",
            m,
            lambda: [discrete_gaussian(Fraction(25), rng) for _ in range(m)],
            repeats,
        )
    )

    recs = [
        (f"u{rng.randrange(int(20000 * scale))}", rng.choice("ABCDEFGH"), rng.random() * 100)
        for _ in range(int(100000 * scale))
    ]

    def dp_mean() -> object:
        acct = PrivacyAccountant(1e9, 0.5)
        return DPAggregator(acct, rng).mean(
            recs, lower=0, upper=100, epsilon=1.0, delta=1e-6, bounds=ContributionBounds(2, 3)
        )

    rows.append(bench("DP mean, 8 private partitions", "records", len(recs), dp_mean, repeats))

    people = [
        {"age": str(rng.randint(18, 90)), "zip": f"021{rng.randint(10, 99)}", "sex": rng.choice("MF")}
        for _ in range(int(10000 * scale))
    ]
    rows.append(
        bench(
            "Mondrian k=10 (3 QIs)",
            "rows",
            len(people),
            lambda: mondrian(people, ["age", "zip", "sex"], 10, categorical=["zip"]),
            repeats,
        )
    )
    hier: dict[str, Hierarchy] = {
        "age": IntervalHierarchy((5, 10, 20)),
        "zip": MaskingHierarchy(3),
        "sex": SuppressionHierarchy(),
    }
    rows.append(
        bench(
            "full-domain generalization k=10",
            "rows",
            len(people),
            lambda: generalize_to_k(people, hier, 10, max_suppression=0.01),
            repeats,
        )
    )

    env = {"python": platform.python_version(), "machine": platform.machine(), "system": platform.system()}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"env": env, "quick": args.quick, "results": rows}, indent=2) + "\n")
    print(f"\n{env}\nwrote {out}")


if __name__ == "__main__":
    main()
