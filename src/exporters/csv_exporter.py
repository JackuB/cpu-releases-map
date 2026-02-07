"""Export CVE data as CSV."""

from __future__ import annotations

import csv
from pathlib import Path

from ..models import ScrapeResult

CSV_COLUMNS = [
    "cve_id",
    "cpu_quarter",
    "cpu_url",
    "product_family",
    "component",
    "cvss_version",
    "base_score",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality",
    "integrity",
    "availability",
    "access_vector",
    "access_complexity",
    "authentication",
    "package_privilege",
    "protocol",
    "remote_exploit",
    "affected_versions",
    "notes",
]


def _sort_key(row: dict) -> tuple:
    """Sort by quarter descending, then base_score descending."""
    quarter = row.get("cpu_quarter", "")
    try:
        score = float(row.get("base_score", "0") or "0")
    except ValueError:
        score = 0.0
    return (-_quarter_to_int(quarter), -score)


def _quarter_to_int(quarter: str) -> int:
    """Convert '2026-Q1' to an integer for sorting (e.g., 20261)."""
    try:
        year, q = quarter.split("-")
        return int(year) * 10 + int(q[1])
    except (ValueError, IndexError):
        return 0


def export_csv(result: ScrapeResult, output_path: Path) -> None:
    """Write one row per CVE appearance, sorted by quarter desc then score desc."""
    rows = []
    for release in result.cpu_releases:
        for entry in release.cve_entries:
            row = {col: getattr(entry, col, "") or "" for col in CSV_COLUMNS}
            rows.append(row)

    rows.sort(key=_sort_key)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
