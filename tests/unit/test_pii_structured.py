from __future__ import annotations

from privkit.pii import Detector, scan_columns
from privkit.pii.structured import header_words

ROWS = [
    {
        "id": str(i),
        "contact_email": f"user{i}@example.com",
        "ssn": f"{100 + i}-45-67{10 + i}",
        "tax_id": f"12345{6000 + i}",
        "note": "ok",
    }
    for i in range(20)
]


def test_scan_columns_classifies() -> None:
    reports = {r.column: r for r in scan_columns(ROWS, Detector())}
    assert reports["contact_email"].dominant == "EMAIL" and reports["contact_email"].prevalence == 1.0
    assert reports["contact_email"].header_hint == "EMAIL"
    assert reports["ssn"].dominant == "US_SSN"
    assert reports["id"].dominant is None and not reports["id"].is_pii
    assert reports["note"].entity_counts == {}
    d = reports["ssn"].to_dict()
    assert d["dominant"] == "US_SSN" and d["n_non_empty"] == 20


def test_header_context_enables_bare_values() -> None:
    rows = [{"customer_ssn": "123456789"}, {"customer_ssn": ""}]
    [report] = scan_columns(rows, Detector(), sample_size=None)
    assert report.dominant == "US_SSN" and report.n_non_empty == 1 and report.n_values == 2


def test_min_prevalence_and_sampling() -> None:
    rows = [{"mixed": "a@example.com"}] + [{"mixed": "nothing"}] * 9
    [r] = scan_columns(rows, Detector(), min_prevalence=0.5)
    assert r.dominant is None and r.entity_counts == {"EMAIL": 1}
    [r2] = scan_columns(rows, Detector(), sample_size=1)
    assert r2.dominant == "EMAIL" and r2.n_values == 1


def test_header_words() -> None:
    assert header_words("Customer_DOB-2") == ["customer", "dob", "2"]
