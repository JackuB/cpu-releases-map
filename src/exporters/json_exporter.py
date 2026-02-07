"""Export CVE data as structured JSON."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from ..models import ScrapeResult


def export_json(result: ScrapeResult, output_path: Path) -> None:
    """Write structured JSON grouped by CPU release and product family."""
    # Collect unique CVE IDs
    all_cve_ids: set[str] = set()
    for release in result.cpu_releases:
        for entry in release.cve_entries:
            all_cve_ids.add(entry.cve_id)

    output = {
        "metadata": {
            "generated_at": result.scrape_timestamp,
            "total_cpus_scraped": result.total_cpus_scraped,
            "total_cpus_failed": result.total_cpus_failed,
            "total_cve_entries": result.total_cves,
            "unique_cve_ids": len(all_cve_ids),
        },
        "cpu_releases": [],
    }

    # Sort releases by quarter descending
    sorted_releases = sorted(
        result.cpu_releases,
        key=lambda r: (r.year, r.month),
        reverse=True,
    )

    for release in sorted_releases:
        if release.error and not release.cve_entries:
            continue

        # Group CVEs by product family
        families: dict[str, list] = defaultdict(list)
        for entry in release.cve_entries:
            entry_dict = asdict(entry)
            # Remove redundant fields that are on the release level
            del entry_dict["cpu_quarter"]
            del entry_dict["cpu_url"]
            del entry_dict["product_family"]
            # Remove None values
            entry_dict = {k: v for k, v in entry_dict.items() if v is not None}
            families[entry.product_family].append(entry_dict)

        release_data = {
            "quarter": release.quarter,
            "label": release.label,
            "url": release.url,
            "is_java_se": release.is_java_se,
            "cve_count": len(release.cve_entries),
            "product_families": dict(families),
        }

        if release.error:
            release_data["error"] = release.error

        output["cpu_releases"].append(release_data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
