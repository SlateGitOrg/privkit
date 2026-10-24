"""Regenerate the bundled demo fixtures (deterministic; all data is fabricated).

uv run python scripts/make_fixtures.py
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

from privkit.evaluation import SyntheticValues, generate_corpus

OUT = Path(__file__).resolve().parent.parent / "examples" / "fixtures"
REGIONS = ["north", "south", "east", "west"]
DIAGNOSES = ["flu", "asthma", "diabetes", "hypertension", "migraine", "none"]


def tickets(rng: random.Random) -> str:
    docs = generate_corpus("dev", 12, seed=42)
    lines = []
    for i, doc in enumerate(docs, start=1):
        lines.append(f"--- ticket #{1000 + i} (priority {rng.choice(['low', 'normal', 'high'])})")
        lines.append(doc.text)
    return "\n".join(lines) + "\n"


def customers(rng: random.Random, values: SyntheticValues, n: int) -> list[dict[str, str]]:
    rows = []
    for i in range(n):
        first, last = rng.choice(values.first), rng.choice(values.last)
        rows.append(
            {
                "customer_id": f"C{i:05d}",
                "name": f"{first} {last}",
                "email": f"{first.lower()}.{last.lower()}{rng.randint(1, 999)}@example.com",
                "phone": values.phone(),
                "card_number": values.card(),
                "ssn": values.ssn(),
                "age": str(min(max(int(rng.gauss(44, 15)), 18), 90)),
                "zip": f"021{rng.randint(30, 49)}",
                "sex": rng.choice("FM"),
                "region": rng.choice(REGIONS),
                "diagnosis": rng.choice(DIAGNOSES),
            }
        )
    return rows


def transactions(rng: random.Random, n_users: int) -> list[dict[str, str]]:
    rows = []
    for u in range(n_users):
        home = rng.choice(REGIONS)
        for _ in range(rng.choice([1, 1, 2, 3, 5, 12])):  # a few heavy users
            region = home if rng.random() < 0.8 else rng.choice(REGIONS)
            amount = round(rng.lognormvariate(3.5, 0.8), 2)
            rows.append({"user_id": f"U{u:05d}", "region": region, "amount": f"{amount:.2f}"})
    rng.shuffle(rows)
    return rows


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20261024)
    values = SyntheticValues(rng, "dev")
    (OUT / "support_tickets.txt").write_text(tickets(rng))
    write_csv(OUT / "customers.csv", customers(rng, values, 2000))
    write_csv(OUT / "transactions.csv", transactions(rng, 3000))
    for f in sorted(OUT.iterdir()):
        print(f"wrote {f.relative_to(OUT.parent.parent)} ({f.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
