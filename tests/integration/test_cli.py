"""End-to-end CLI tests on the bundled fixtures (no network, no Docker)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from privkit.cli import EXIT_BUDGET, EXIT_ERROR, EXIT_FINDINGS, main

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "examples" / "fixtures"
KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


@pytest.fixture(autouse=True)
def demo_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVKIT_KEY", KEY)


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_keygen(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "keygen", "--bytes", "16")
    assert code == 0 and len(out.strip()) == 32


def test_scan_text_and_json(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = run(capsys, "scan", str(FIX / "support_tickets.txt"))
    assert code == 0 and "findings (" in out
    code, out, _ = run(capsys, "scan", str(FIX / "support_tickets.txt"), "--json", "--entities", "EMAIL")
    findings = json.loads(out)
    assert findings and {f["entity"] for f in findings} == {"EMAIL"} and "text" not in findings[0]
    code, out, _ = run(capsys, "scan", str(FIX / "support_tickets.txt"), "--json", "--show-values")
    assert "text" in json.loads(out)[0]
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing to see here\n")
    assert run(capsys, "scan", str(clean), "--fail-on-findings")[0] == 0
    assert run(capsys, "scan", str(FIX / "support_tickets.txt"), "--fail-on-findings")[0] == EXIT_FINDINGS
    code, out, _ = run(capsys, "scan", str(clean), "--allow", "x")
    assert "0 findings (none)" in out


def test_scan_table(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan-table", str(FIX / "customers.csv"), "--json", "--sample", "300")
    reports = {r["column"]: r for r in json.loads(out)}
    assert reports["email"]["dominant"] == "EMAIL"
    assert reports["card_number"]["dominant"] == "CREDIT_CARD"
    assert reports["ssn"]["dominant"] == "US_SSN"
    assert reports["phone"]["dominant"] == "PHONE"
    assert reports["region"]["dominant"] is None
    code, out, _ = run(capsys, "scan-table", str(FIX / "customers.csv"), "--sample", "50")
    assert code == 0 and "card_number" in out


@pytest.mark.parametrize("mode", ["redact", "mask", "pseudonymize"])
def test_redact_modes(capsys: pytest.CaptureFixture[str], tmp_path: Path, mode: str) -> None:
    out_file = tmp_path / "out.txt"
    code, _, _ = run(capsys, "redact", str(FIX / "support_tickets.txt"), "--mode", mode, "-o", str(out_file))
    text = out_file.read_text()
    assert code == 0 and "@inbox.example.io" not in text


def test_tokenize_detokenize_text_roundtrip(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    src = FIX / "support_tickets.txt"
    tok = tmp_path / "tok.txt"
    back = tmp_path / "back.txt"
    assert run(capsys, "redact", str(src), "--mode", "tokenize", "--tagged", "-o", str(tok))[0] == 0
    assert "[[" in tok.read_text()
    assert run(capsys, "detokenize", str(tok), "-o", str(back))[0] == 0
    assert back.read_text() == src.read_text()


def test_tokenize_table_roundtrip(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    out = tmp_path / "tok.csv"
    back = tmp_path / "back.csv"
    cols = "card_number=CREDIT_CARD,ssn=US_SSN,email=EMAIL,phone=PHONE"
    assert run(capsys, "tokenize-table", str(FIX / "customers.csv"), "--columns", cols, "-o", str(out))[0] == 0
    original = list(csv.DictReader((FIX / "customers.csv").read_text().splitlines()))
    tokenized = list(csv.DictReader(out.read_text().splitlines()))
    assert all(
        a["ssn"] != b["ssn"] and len(a["ssn"]) == len(b["ssn"]) for a, b in zip(original, tokenized, strict=True)
    )
    assert all(a["card_number"][-4:] == b["card_number"][-4:] for a, b in zip(original, tokenized, strict=True))
    argv = ["tokenize-table", str(out), "--columns", cols, "--reverse", "-o", str(back)]
    assert run(capsys, *argv)[0] == 0
    assert back.read_text() == (FIX / "customers.csv").read_text()


def test_tokenize_table_ff3_and_jsonl(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    src = tmp_path / "in.jsonl"
    src.write_text('{"ssn": "123-45-6789", "n": 1}\n\n{"ssn": "", "n": null}\n')
    out = tmp_path / "out.jsonl"
    code, _, _ = run(
        capsys, "tokenize-table", str(src), "--columns", "ssn=US_SSN", "--algorithm", "ff3-1", "-o", str(out)
    )
    lines = [json.loads(x) for x in out.read_text().splitlines()]
    assert code == 0 and lines[0]["ssn"] != "123-45-6789" and lines[1] == {"ssn": "", "n": ""}


def test_tokenize_table_errors(capsys: pytest.CaptureFixture[str]) -> None:
    f = str(FIX / "customers.csv")
    assert run(capsys, "tokenize-table", f, "--columns", "card_number=NOPE")[0] == EXIT_ERROR
    assert run(capsys, "tokenize-table", f, "--columns", "missing=US_SSN")[0] == EXIT_ERROR
    assert run(capsys, "tokenize-table", f, "--columns", ",")[0] == EXIT_ERROR


def test_fpe_nist_sample_via_cli(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NIST_KEY", "2B7E151628AED2A6ABF7158809CF4F3C")
    code, out, _ = run(capsys, "fpe", "encrypt", "0123456789", "--key-env", "NIST_KEY")
    assert code == 0 and out.strip() == "2433477484"
    code, out, _ = run(
        capsys, "fpe", "decrypt", "6124200773", "--key-env", "NIST_KEY", "--tweak", "39383736353433323130"
    )
    assert out.strip() == "0123456789"
    code, out, _ = run(
        capsys, "fpe", "encrypt", "abcdef", "--alphabet", "lower", "--algorithm", "ff3-1", "--tweak", "00" * 7
    )
    assert code == 0 and len(out.strip()) == 6


def test_missing_key_is_an_error(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PRIVKIT_KEY")
    code, _, err = run(capsys, "fpe", "encrypt", "0123456789")
    assert code == EXIT_ERROR and "PRIVKIT_KEY" in err


def test_kanon_report_generalize_and_mondrian(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    f = str(FIX / "customers.csv")
    code, out, _ = run(capsys, "kanon", f, "--qi", "age,zip,sex", "--sensitive", "diagnosis", "-k", "5", "--json")
    payload = json.loads(out)
    assert code == 0 and not payload["before"]["satisfies_k"]
    gen = tmp_path / "gen.csv"
    argv = ["kanon", f, "--qi", "age,zip,sex", "-k", "5", "--generalize", "age=interval:5,10,20",
            "--generalize", "zip=mask:3", "--max-suppression", "0.02", "-o", str(gen), "--json"]  # fmt: skip
    code, out, _ = run(capsys, *argv)
    payload = json.loads(out)
    assert payload["after"]["satisfies_k"] and gen.exists()
    code, out, _ = run(
        capsys,
        "kanon",
        f,
        "--qi",
        "age,zip,sex",
        "--sensitive",
        "diagnosis",
        "-k",
        "5",
        "--mondrian",
        "--categorical",
        "zip",
    )
    assert code == 0 and "after: k=" in out and "VIOLATED" in out.splitlines()[0] and "mondrian:" in out
    bad = ["kanon", f, "--qi", "age", "-k", "5", "--generalize", "zip=mask:3"]
    assert run(capsys, *bad)[0] == EXIT_ERROR
    assert run(capsys, "kanon", f, "--qi", "age", "-k", "5", "--generalize", "nonsense")[0] == EXIT_ERROR


def test_dp_queries_with_ledger(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.json"
    tx = str(FIX / "transactions.csv")
    assert (
        run(capsys, "budget", "init", str(ledger), "--epsilon", "1.0", "--delta", "1e-5", "--composition", "rdp")[0]
        == 0
    )
    assert run(capsys, "budget", "init", str(ledger))[0] == EXIT_ERROR  # refuses to overwrite
    code, out, err = run(capsys, "dp", tx, "--metric", "count", "--privacy-unit", "user_id", "--group-by", "region",
                         "--epsilon", "0.3", "--delta", "1e-6", "--max-partitions", "2", "--ledger", str(ledger),
                         "--insecure-seed", "7", "--json")  # fmt: skip
    payload = json.loads(out)
    assert code == 0 and "NOT private" in err and payload["private_partition_selection"]
    assert {r["partition"] for r in payload["rows"]} == {"north", "south", "east", "west"}
    code, out, _ = run(capsys, "dp", tx, "--metric", "mean", "--privacy-unit", "user_id", "--value", "amount",
                       "--lower", "0", "--upper", "200", "--epsilon", "0.4", "--ledger", str(ledger),
                       "--group-by", "region", "--public-partitions", "north,south,east,west")  # fmt: skip
    assert code == 0 and "budget spent" in out
    code, _, err = run(
        capsys, "dp", tx, "--metric", "count", "--privacy-unit", "user_id", "--epsilon", "0.5", "--ledger", str(ledger)
    )
    assert code == EXIT_BUDGET and "budget exceeded" in err
    code, out, _ = run(capsys, "budget", "show", str(ledger), "--json")
    state = json.loads(out)
    assert len(state["charges"]) == 4 and state["spent"]["epsilon"] <= 1.0
    code, out, _ = run(capsys, "budget", "show", str(ledger))
    assert "composition=rdp" in out


def test_dp_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    tx = str(FIX / "transactions.csv")
    assert run(capsys, "dp", tx, "--metric", "sum", "--privacy-unit", "user_id", "--epsilon", "1")[0] == EXIT_ERROR
    assert run(capsys, "dp", tx, "--metric", "count", "--privacy-unit", "nope", "--epsilon", "1")[0] == EXIT_ERROR
    assert run(capsys, "dp", tx, "--metric", "sum", "--privacy-unit", "user_id", "--value", "region",
               "--lower", "0", "--upper", "1", "--epsilon", "1")[0] == EXIT_ERROR  # fmt: skip
    missing = str(tmp_path / "nope.json")
    assert (
        run(capsys, "dp", tx, "--metric", "count", "--privacy-unit", "user_id", "--epsilon", "1", "--ledger", missing)[
            0
        ]
        == EXIT_ERROR
    )
    code, out, _ = run(capsys, "dp", tx, "--metric", "sum", "--privacy-unit", "user_id", "--value", "amount",
                       "--lower", "0", "--upper", "100", "--epsilon", "1")  # fmt: skip
    assert code == 0 and "__all__" in out


def test_eval_command(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "eval", "--docs", "100", "--json")
    payload = json.loads(out)
    assert code == 0 and payload["micro"]["recall"] > 0.9
    code, out, _ = run(capsys, "eval", "--docs", "50", "--split", "dev")
    assert "**micro**" in out


def test_verbose_logging_and_bad_input(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, _ = run(capsys, "-v", "scan", str(FIX / "support_tickets.txt"))
    assert code == 0
    assert run(capsys, "scan", str(tmp_path / "absent.txt"))[0] == EXIT_ERROR
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json}\n")
    assert run(capsys, "scan-table", str(bad))[0] == EXIT_ERROR
    bad.write_text("[1, 2]\n")
    assert run(capsys, "scan-table", str(bad))[0] == EXIT_ERROR
