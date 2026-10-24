"""Reading and writing tables (CSV / JSON Lines) and text, with ``-`` meaning stdin/stdout."""

from __future__ import annotations

import csv
import io
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from privkit.errors import InvalidInputError

TableFormat = Literal["csv", "jsonl"]


def _detect(path: str, fmt: TableFormat | None) -> TableFormat:
    if fmt is not None:
        return fmt
    return "jsonl" if path.endswith((".jsonl", ".ndjson")) else "csv"


def read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidInputError(f"cannot read {path}: {exc.strerror}") from exc


def write_text(path: str | None, text: str) -> None:
    if path is None or path == "-":
        sys.stdout.write(text)
        sys.stdout.flush()
    else:
        Path(path).write_text(text, encoding="utf-8")


def read_rows(path: str, fmt: TableFormat | None = None) -> tuple[list[dict[str, str]], list[str]]:
    """Return (rows, column names). All values are strings; JSON values are stringified."""
    text = read_text(path)
    kind = _detect(path, fmt)
    if kind == "csv":
        reader = csv.DictReader(io.StringIO(text))
        rows = [{k: (v if v is not None else "") for k, v in r.items() if k is not None} for r in reader]
        return rows, list(reader.fieldnames or [])
    rows = []
    columns: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            raise InvalidInputError(f"line {lineno} is not valid JSON") from None
        if not isinstance(obj, dict):
            raise InvalidInputError(f"line {lineno} is not a JSON object")
        row = {str(k): "" if v is None else str(v) for k, v in obj.items()}
        for k in row:
            if k not in columns:
                columns.append(k)
        rows.append(row)
    return rows, columns


def format_rows(rows: Sequence[dict[str, str]], columns: Sequence[str], fmt: TableFormat) -> str:
    if fmt == "jsonl":
        return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(columns), extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def write_rows(
    path: str | None, rows: Sequence[dict[str, str]], columns: Sequence[str], fmt: TableFormat | None = None
) -> None:
    write_text(path, format_rows(rows, columns, _detect(path or "-", fmt)))
