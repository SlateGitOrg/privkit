"""Detector precision / recall on the synthetic labeled corpus (dev and held-out test splits).

    uv run python -u scripts/eval_detector.py [--docs 2000] [--seed 2026] [--out eval/results.json]

Regex+checksum recognizers are always evaluated. If the optional spaCy model is
installed (``make ner-model``), a second run adds NER and scores PERSON/LOCATION.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from privkit.evaluation import evaluate, generate_corpus
from privkit.pii import Detector, SpacyNerRecognizer, ner_available


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--out", default="eval/results.json")
    args = parser.parse_args()

    configs: list[tuple[str, Detector, set[str]]] = []
    regex = Detector()
    configs.append(("regex+checksum", regex, set(regex.entities)))
    if ner_available():
        ner = Detector(extra=[SpacyNerRecognizer()])
        configs.append(("regex+checksum+spacy", ner, set(ner.entities) | {"PERSON", "LOCATION"}))
    else:
        print("spaCy model not installed: skipping the NER configuration (run `make ner-model`).")

    results: dict[str, object] = {"docs_per_split": args.docs, "seed": args.seed, "runs": []}
    runs: list[dict[str, object]] = []
    for split in ("dev", "test"):
        docs = generate_corpus(split, args.docs, args.seed)
        chars = sum(len(d.text) for d in docs)
        for name, det, entities in configs:
            start = time.perf_counter()
            report = evaluate(docs, det.analyze, entities)
            elapsed = time.perf_counter() - start
            print(f"\n## split={split} detector={name} docs={len(docs)} ({chars:,} chars, {elapsed:.2f}s)\n")
            print(report.to_markdown())
            runs.append({"split": split, "detector": name, "seconds": round(elapsed, 3), **report.to_dict()})
    results["runs"] = runs
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
