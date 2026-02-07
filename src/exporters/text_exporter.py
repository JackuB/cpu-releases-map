"""Export unique CVE IDs as plain text, one per line."""

from __future__ import annotations

from pathlib import Path

from ..models import ScrapeResult


def export_text(result: ScrapeResult, output_path: Path) -> None:
    """Write all unique CVE IDs sorted lexicographically, one per line."""
    cve_ids: set[str] = set()
    for release in result.cpu_releases:
        for entry in release.cve_entries:
            cve_ids.add(entry.cve_id)

    sorted_ids = sorted(cve_ids)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for cve_id in sorted_ids:
            f.write(cve_id + "\n")
