"""Export CVE data as a human-readable Markdown summary."""

from __future__ import annotations

from pathlib import Path

from ..models import ScrapeResult


def export_markdown(result: ScrapeResult, output_path: Path) -> None:
    """Write a Markdown overview with stats and per-CPU breakdown."""
    # Collect unique CVE IDs
    all_cve_ids: set[str] = set()
    for release in result.cpu_releases:
        for entry in release.cve_entries:
            all_cve_ids.add(entry.cve_id)

    lines = [
        "# Oracle Critical Patch Update - CVE Summary",
        "",
        f"Generated: {result.scrape_timestamp}",
        "",
        "## Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| CPUs scraped | {result.total_cpus_scraped} |",
        f"| CPUs failed | {result.total_cpus_failed} |",
        f"| Total CVE entries | {result.total_cves} |",
        f"| Unique CVE IDs | {len(all_cve_ids)} |",
        "",
    ]

    # Per-CPU breakdown
    lines.append("## Per-CPU Breakdown")
    lines.append("")
    lines.append("| Quarter | Label | CVEs | Product Families | Highest CVSS |")
    lines.append("|---------|-------|------|-----------------|-------------|")

    sorted_releases = sorted(
        result.cpu_releases,
        key=lambda r: (r.year, r.month),
        reverse=True,
    )

    for release in sorted_releases:
        if release.error and not release.cve_entries:
            lines.append(
                f"| {release.quarter} | [{release.label}]({release.url}) "
                f"| ERROR | - | - |"
            )
            continue

        families = set(e.product_family for e in release.cve_entries)
        max_score = 0.0
        for entry in release.cve_entries:
            try:
                score = float(entry.base_score)
                max_score = max(max_score, score)
            except (ValueError, TypeError):
                pass

        score_str = f"{max_score:.1f}" if max_score > 0 else "-"
        lines.append(
            f"| {release.quarter} | [{release.label}]({release.url}) "
            f"| {len(release.cve_entries)} | {len(families)} | {score_str} |"
        )

    # Errors section
    if result.errors:
        lines.append("")
        lines.append("## Errors")
        lines.append("")
        for error in result.errors:
            lines.append(f"- {error}")

    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
