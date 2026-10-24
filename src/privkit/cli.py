"""``privkit`` command-line interface.

Exit codes: 0 success, 2 usage/configuration/input error, 3 findings present
(``scan --fail-on-findings``), 4 privacy budget exceeded.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from privkit import __version__
from privkit.dp import (
    Composition,
    ContributionBounds,
    DPAggregator,
    DPResult,
    PrivacyAccountant,
    insecure_seeded_rng,
    secure_rng,
)
from privkit.errors import BudgetExceededError, ConfigurationError, InvalidInputError, PrivkitError
from privkit.fpe import Algorithm, FormatPreservingCipher, alphabet_by_name
from privkit.io import read_rows, read_text, write_rows, write_text
from privkit.kanon import Hierarchy, assess, generalize_to_k, mondrian, parse_hierarchy
from privkit.keys import DEFAULT_KEY_ENV, derive_key, generate_key_hex, key_from_env
from privkit.pii import (
    Detector,
    Mask,
    Operator,
    Pseudonymize,
    Redact,
    SpacyNerRecognizer,
    Tokenize,
    anonymize,
    detokenize_text,
    scan_columns,
)
from privkit.tokens import DEFAULT_POLICIES, Tokenizer, TokenPolicy

logger = logging.getLogger("privkit")

EXIT_ERROR, EXIT_FINDINGS, EXIT_BUDGET = 2, 3, 4


def _csv_list(text: str | None) -> list[str]:
    return [x.strip() for x in text.split(",") if x.strip()] if text else []


def _print_json(obj: object) -> None:
    write_text("-", json.dumps(obj, indent=2, ensure_ascii=False, default=str) + "\n")


def _detector(args: argparse.Namespace) -> Detector:
    extra = [SpacyNerRecognizer(model=args.ner_model)] if getattr(args, "ner", False) else []
    return Detector(threshold=args.threshold, extra=extra, allow_list=_csv_list(getattr(args, "allow", None)))


# -- commands -------------------------------------------------------------------
def cmd_keygen(args: argparse.Namespace) -> int:
    write_text("-", generate_key_hex(args.bytes) + "\n")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    text = read_text(args.input)
    entities = _csv_list(args.entities) or None
    findings = _detector(args).analyze(text, entities=entities)
    if args.json:
        _print_json([f.to_dict(include_text=args.show_values) for f in findings])
    else:
        for f in findings:
            value = f" {f.text!r}" if args.show_values else ""
            write_text("-", f"{f.start:>6}-{f.end:<6} {f.entity:<15} {f.score:.2f}{value}\n")
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.entity] = counts.get(f.entity, 0) + 1
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
        write_text("-", f"{len(findings)} findings ({summary})\n")
    return EXIT_FINDINGS if args.fail_on_findings and findings else 0


def cmd_scan_table(args: argparse.Namespace) -> int:
    rows, _ = read_rows(args.input, args.format)
    reports = scan_columns(rows, _detector(args), sample_size=args.sample, min_prevalence=args.min_prevalence)
    if args.json:
        _print_json([r.to_dict() for r in reports])
        return 0
    write_text("-", f"{'column':<20} {'pii':<15} {'prevalence':>10}  header-hint\n")
    for r in reports:
        write_text("-", f"{r.column:<20} {r.dominant or '-':<15} {r.prevalence:>10.0%}  {r.header_hint or '-'}\n")
    return 0


def _operator(args: argparse.Namespace) -> Operator:
    if args.mode == "redact":
        return Redact()
    if args.mode == "mask":
        return Mask(keep_last=args.keep_last)
    key = key_from_env(args.key_env)
    if args.mode == "pseudonymize":
        return Pseudonymize(derive_key(key, "privkit/v1/pseudonym"))
    return Tokenize(Tokenizer(key), tagged=args.tagged)


def cmd_redact(args: argparse.Namespace) -> int:
    text = read_text(args.input)
    findings = _detector(args).analyze(text, entities=_csv_list(args.entities) or None)
    result = anonymize(text, findings, default=_operator(args))
    write_text(args.output, result.text)
    logger.info("replaced %d findings", len(result.replacements))
    return 0


def cmd_detokenize(args: argparse.Namespace) -> int:
    tokenizer = Tokenizer(key_from_env(args.key_env))
    write_text(args.output, detokenize_text(read_text(args.input), tokenizer))
    return 0


def _column_policies(spec: str, algorithm: Algorithm) -> dict[str, TokenPolicy]:
    policies = {}
    for item in _csv_list(spec):
        column, _, policy_name = item.partition("=")
        if policy_name not in DEFAULT_POLICIES:
            raise ConfigurationError(f"unknown policy {policy_name!r}; known: {', '.join(sorted(DEFAULT_POLICIES))}")
        # The policy name includes the column, so each column gets its own derived key.
        policies[column] = dataclasses.replace(
            DEFAULT_POLICIES[policy_name], name=f"{policy_name}@{column}", algorithm=algorithm
        )
    if not policies:
        raise ConfigurationError("give --columns like card=CREDIT_CARD,ssn=US_SSN")
    return policies


def cmd_tokenize_table(args: argparse.Namespace) -> int:
    rows, columns = read_rows(args.input, args.format)
    policies = _column_policies(args.columns, Algorithm(args.algorithm))
    missing = [c for c in policies if c not in columns]
    if missing:
        raise InvalidInputError(f"columns not found: {', '.join(missing)}")
    tokenizer = Tokenizer(key_from_env(args.key_env), policies=policies)
    for row in rows:
        for column in policies:
            value = row.get(column, "")
            if value:
                row[column] = tokenizer.detokenize(value, column) if args.reverse else tokenizer.tokenize(value, column)
    write_rows(args.output, rows, columns, args.format)
    return 0


def cmd_fpe(args: argparse.Namespace) -> int:
    key = key_from_env(args.key_env)
    cipher = FormatPreservingCipher(key, alphabet_by_name(args.alphabet), Algorithm(args.algorithm))
    tweak = bytes.fromhex(args.tweak) if args.tweak else None
    op = cipher.encrypt if args.action == "encrypt" else cipher.decrypt
    write_text("-", op(args.value, tweak) + "\n")
    return 0


def _hierarchies(specs: Sequence[str]) -> dict[str, Hierarchy]:
    out: dict[str, Hierarchy] = {}
    for spec in specs:
        column, sep, rule = spec.partition("=")
        if not sep:
            raise ConfigurationError(f"--generalize expects column=rule, got {spec!r}")
        out[column] = parse_hierarchy(rule)
    return out


def cmd_kanon(args: argparse.Namespace) -> int:
    rows, columns = read_rows(args.input, args.format)
    qis = _csv_list(args.qi)
    sensitive = _csv_list(args.sensitive)
    before = assess(rows, qis, sensitive=sensitive, k=args.k)
    payload: dict[str, Any] = {"before": before.to_dict()}
    output_rows = None
    if args.generalize:
        hier = _hierarchies(args.generalize)
        unknown = set(hier) - set(qis)
        if unknown:
            raise ConfigurationError(f"--generalize columns must be quasi-identifiers: {sorted(unknown)}")
        for q in qis:
            hier.setdefault(q, parse_hierarchy("suppress"))
        res = generalize_to_k(rows, hier, args.k, max_suppression=args.max_suppression)
        payload["generalization"] = res.to_dict()
        output_rows = res.rows
    elif args.mondrian:
        mres = mondrian(rows, qis, args.k, categorical=_csv_list(args.categorical))
        payload["mondrian"] = mres.to_dict()
        output_rows = mres.rows
    if output_rows is not None:
        payload["after"] = assess(output_rows, qis, sensitive=sensitive, k=args.k).to_dict()
        if args.output:
            write_rows(args.output, output_rows, columns, args.format)
    if args.json:
        _print_json(payload)
    else:
        for stage in ("before", "after"):
            if stage in payload:
                r = payload[stage]
                write_text(
                    "-",
                    f"{stage:>6}: k={r['k']} (target {r['target_k']}, {'OK' if r['satisfies_k'] else 'VIOLATED'}) "
                    f"classes={r['n_classes']} at-risk={r['records_at_risk']}/{r['n_records']} "
                    f"unique={r['unique_records']} max-risk={r['prosecutor_risk_max']:.3f}\n",
                )
                for s in r["sensitive"]:
                    write_text(
                        "-",
                        f"        {s['attribute']}: distinct-l={s['distinct_l']} entropy-l={s['entropy_l']} "
                        f"t={s['t_closeness']}\n",
                    )
        for key in ("generalization", "mondrian"):
            if key in payload:
                write_text("-", f"{key}: {json.dumps(payload[key])}\n")
    return 0


def _load_accountant(args: argparse.Namespace) -> PrivacyAccountant:
    if args.ledger:
        path = Path(args.ledger)
        if not path.exists():
            raise ConfigurationError(f"ledger {path} does not exist; create it with `privkit budget init`")
        return PrivacyAccountant.load(path)
    return PrivacyAccountant(args.epsilon, args.delta)


def _result_payload(res: DPResult, acct: PrivacyAccountant) -> dict[str, object]:
    spent = acct.spent()
    return {
        "metric": res.metric.value,
        "noise": res.noise.value,
        "mechanisms": list(res.mechanisms),
        "private_partition_selection": res.selected_partitions,
        "query_cost": {"epsilon": res.cost.epsilon, "delta": res.cost.delta},
        "budget_spent": {"epsilon": spent.epsilon, "delta": spent.delta},
        "budget_total": {"epsilon": acct.budget.epsilon, "delta": acct.budget.delta},
        "rows": res.to_rows(),
    }


def cmd_dp(args: argparse.Namespace) -> int:
    rows, _ = read_rows(args.input, args.format)
    acct = _load_accountant(args)
    # A seeded RNG (demo/testing only) logs a NOT-private warning.
    rng = insecure_seeded_rng(args.insecure_seed) if args.insecure_seed is not None else secure_rng()
    agg = DPAggregator(acct, rng)
    records = []
    for i, row in enumerate(rows):
        try:
            unit = row[args.privacy_unit]
            part = row[args.group_by] if args.group_by else "__all__"
            value = float(row[args.value]) if args.value else 1.0
        except KeyError as exc:
            raise InvalidInputError(f"row {i} lacks column {exc.args[0]!r}") from None
        except ValueError:
            raise InvalidInputError(f"row {i}: column {args.value!r} is not numeric") from None
        records.append((unit, part, value))
    public = _csv_list(args.public_partitions) or (None if args.group_by else ["__all__"])
    common: dict[str, Any] = {
        "epsilon": args.epsilon,
        "delta": args.delta,
        "noise": args.noise,
        "bounds": ContributionBounds(args.max_partitions, args.max_contributions),
        "public_partitions": public,
        "label": args.label or args.metric,
    }
    if args.integer and args.metric != "sum":
        raise ConfigurationError("--integer applies only to --metric sum")
    if args.metric == "count":
        res = agg.count(records, **common)
    else:
        if args.value is None or args.lower is None or args.upper is None:
            raise ConfigurationError(f"{args.metric} needs --value, --lower and --upper")
        if args.metric == "sum":
            res = agg.sum(records, lower=args.lower, upper=args.upper, integer=args.integer, **common)
        else:
            res = agg.mean(records, lower=args.lower, upper=args.upper, **common)
    if args.ledger:
        acct.save(Path(args.ledger))
    if args.json:
        _print_json(_result_payload(res, acct))
    else:
        write_text("-", f"{'partition':<20} {'value':>14} {'±95%':>10}\n")
        for key, released in sorted(res.partitions.items(), key=lambda kv: str(kv[0])):
            write_text("-", f"{key!s:<20} {released.value:>14.2f} {released.ci95:>10.2f}\n")
        spent, total = acct.spent(), acct.budget
        write_text(
            "-",
            f"query cost eps={res.cost.epsilon:.4g} delta={res.cost.delta:.3g}; budget spent "
            f"eps={spent.epsilon:.4g}/{total.epsilon:.4g} delta={spent.delta:.3g}/{total.delta:.3g}\n",
        )
    return 0


def cmd_budget(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if args.action == "init":
        if path.exists() and not args.force:
            raise ConfigurationError(f"{path} exists; pass --force to overwrite")
        PrivacyAccountant(args.epsilon, args.delta, Composition(args.composition)).save(path)
    acct = PrivacyAccountant.load(path)
    state = acct.to_dict()
    if args.json:
        _print_json(state)
    else:
        spent, budget = acct.spent(), acct.budget
        write_text(
            "-",
            f"composition={acct.composition.value} spent eps={spent.epsilon:.4g}/{budget.epsilon:.4g} "
            f"delta={spent.delta:.3g}/{budget.delta:.3g}; {len(acct.ledger)} charges\n",
        )
        for c in acct.ledger:
            write_text("-", f"  - {c.label:<28} {c.mechanism:<18} eps={c.cost.epsilon:.4g} delta={c.cost.delta:.3g}\n")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from privkit.evaluation import evaluate, generate_corpus

    detector = _detector(args)
    entities = set(detector.entities)
    if args.ner:
        entities |= {"PERSON", "LOCATION"}
    docs = generate_corpus(args.split, args.docs, args.seed)
    report = evaluate(docs, detector.analyze, entities)
    if args.json:
        _print_json({"split": args.split, "seed": args.seed, "ner": args.ner, **report.to_dict()})
    else:
        write_text("-", f"split={args.split} docs={args.docs} seed={args.seed} ner={args.ner}\n")
        write_text("-", report.to_markdown() + "\n")
    return 0


# -- parser -----------------------------------------------------------------------
def _add_detector_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--threshold", type=float, default=0.5, help="minimum finding score (default 0.5)")
    p.add_argument("--ner", action="store_true", help="also run spaCy NER (needs the 'ner' extra and model)")
    p.add_argument("--ner-model", default="en_core_web_sm")
    p.add_argument("--allow", help="comma-separated exact values never to report")


def _add_key_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--key-env", default=DEFAULT_KEY_ENV, help=f"env var holding the master key (default {DEFAULT_KEY_ENV})"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privkit", description="Privacy toolkit for data pipelines.")
    parser.add_argument("--version", action="version", version=f"privkit {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="log to stderr (-v info, -vv debug)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="print a new random master key (hex)")
    p.add_argument("--bytes", type=int, default=32, choices=[16, 24, 32])
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("scan", help="detect PII in a text file")
    p.add_argument("input", help="text file or - for stdin")
    p.add_argument("--entities", help="comma-separated entity types to report")
    p.add_argument("--json", action="store_true")
    p.add_argument("--show-values", action="store_true", help="include the matched values in the output")
    p.add_argument("--fail-on-findings", action="store_true", help="exit 3 when anything is found (CI gate)")
    _add_detector_args(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("scan-table", help="classify CSV/JSONL columns by the PII they contain")
    p.add_argument("input")
    p.add_argument("--format", choices=["csv", "jsonl"])
    p.add_argument("--sample", type=int, default=2000)
    p.add_argument("--min-prevalence", type=float, default=0.3)
    p.add_argument("--json", action="store_true")
    _add_detector_args(p)
    p.set_defaults(func=cmd_scan_table)

    p = sub.add_parser("redact", help="replace PII in text (redact, mask, pseudonymize or tokenize)")
    p.add_argument("input")
    p.add_argument("-o", "--output")
    p.add_argument("--mode", choices=["redact", "mask", "pseudonymize", "tokenize"], default="redact")
    p.add_argument("--tagged", action="store_true", help="wrap tokens as [[ENTITY:token]] so they can be reversed")
    p.add_argument("--keep-last", type=int, default=4, help="characters kept by --mode mask")
    p.add_argument("--entities", help="comma-separated entity types to replace")
    _add_key_arg(p)
    _add_detector_args(p)
    p.set_defaults(func=cmd_redact)

    p = sub.add_parser("detokenize", help="restore [[ENTITY:token]] tags in text")
    p.add_argument("input")
    p.add_argument("-o", "--output")
    _add_key_arg(p)
    p.set_defaults(func=cmd_detokenize)

    p = sub.add_parser("tokenize-table", help="format-preserving tokenization of CSV/JSONL columns")
    p.add_argument("input")
    p.add_argument("--columns", required=True, help="column=POLICY pairs, e.g. card=CREDIT_CARD,ssn=US_SSN")
    p.add_argument("--reverse", action="store_true", help="detokenize instead")
    p.add_argument("--algorithm", choices=[a.value for a in Algorithm], default="ff1")
    p.add_argument("--format", choices=["csv", "jsonl"])
    p.add_argument("-o", "--output")
    _add_key_arg(p)
    p.set_defaults(func=cmd_tokenize_table)

    p = sub.add_parser("fpe", help="raw FF1 / FF3-1 encryption of one value")
    p.add_argument("action", choices=["encrypt", "decrypt"])
    p.add_argument("value")
    p.add_argument("--alphabet", default="digits", help="digits, lower, upper, hex, alnum, alnum-lower, alnum-upper")
    p.add_argument("--algorithm", choices=[a.value for a in Algorithm], default="ff1")
    p.add_argument("--tweak", help="tweak as hex (FF3-1: exactly 7 bytes)")
    _add_key_arg(p)
    p.set_defaults(func=cmd_fpe)

    p = sub.add_parser("kanon", help="k-anonymity / l-diversity / t-closeness report and anonymization")
    p.add_argument("input")
    p.add_argument("--qi", required=True, help="comma-separated quasi-identifier columns")
    p.add_argument("--sensitive", help="comma-separated sensitive columns (l-diversity, t-closeness)")
    p.add_argument("-k", type=int, required=True)
    group = p.add_mutually_exclusive_group()
    group.add_argument("--generalize", action="append", default=[], metavar="COL=RULE",
                       help="hierarchy per QI: interval:5,10,20 | mask:3 | suppress (repeatable)")  # fmt: skip
    group.add_argument("--mondrian", action="store_true", help="use Mondrian multidimensional partitioning")
    p.add_argument("--categorical", help="QIs Mondrian must treat as categorical (e.g. zip)")
    p.add_argument("--max-suppression", type=float, default=0.0)
    p.add_argument("--format", choices=["csv", "jsonl"])
    p.add_argument("-o", "--output", help="write the anonymized table here")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_kanon)

    p = sub.add_parser("dp", help="differentially private count / sum / mean")
    p.add_argument("input")
    p.add_argument("--metric", choices=["count", "sum", "mean"], required=True)
    p.add_argument("--privacy-unit", required=True, help="column identifying the protected individual")
    p.add_argument("--group-by")
    p.add_argument("--value", help="numeric column for sum/mean")
    p.add_argument("--lower", type=float)
    p.add_argument("--upper", type=float)
    p.add_argument(
        "--integer",
        action="store_true",
        help="sum only: integer-valued query (integer bounds, values rounded) noised with the exact discrete sampler",
    )
    p.add_argument("--epsilon", type=float, required=True)
    p.add_argument("--delta", type=float, default=0.0)
    p.add_argument("--noise", choices=["laplace", "gaussian"], default="laplace")
    p.add_argument("--max-partitions", type=int, default=1, help="partitions one unit may contribute to (L0)")
    p.add_argument("--max-contributions", type=int, default=1, help="records per unit per partition (Linf)")
    p.add_argument("--public-partitions", help="comma-separated known group keys (skips private selection)")
    p.add_argument("--ledger", help="persistent privacy-budget ledger (see `privkit budget`)")
    p.add_argument("--label")
    p.add_argument("--insecure-seed", type=int, help="TESTING ONLY: reproducible, non-private noise")
    p.add_argument("--format", choices=["csv", "jsonl"])
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_dp)

    p = sub.add_parser("budget", help="create or inspect a privacy-budget ledger")
    p.add_argument("action", choices=["init", "show"])
    p.add_argument("ledger")
    p.add_argument("--epsilon", type=float, default=1.0)
    p.add_argument("--delta", type=float, default=0.0)
    p.add_argument("--composition", choices=[c.value for c in Composition], default="basic")
    p.add_argument("--force", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_budget)

    p = sub.add_parser("eval", help="precision/recall of the detector on the synthetic labeled corpus")
    p.add_argument("--split", choices=["dev", "test"], default="test")
    p.add_argument("--docs", type=int, default=2000)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--json", action="store_true")
    _add_detector_args(p)
    p.set_defaults(func=cmd_eval)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    level = {0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    logging.basicConfig(level=level, stream=sys.stderr, format="privkit: %(levelname)s: %(message)s")
    logging.getLogger("privkit").setLevel(level)
    try:
        code: int = args.func(args)
    except BudgetExceededError as exc:
        sys.stderr.write(f"privkit: budget exceeded: {exc}\n")
        return EXIT_BUDGET
    except PrivkitError as exc:
        sys.stderr.write(f"privkit: error: {exc}\n")
        return EXIT_ERROR
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
