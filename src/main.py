"""CLI entry point and orchestrator for the Oracle CPU CVE scraper."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from .discovery import discover_cpu_releases
from .exporters.csv_exporter import export_csv
from .exporters.json_exporter import export_json
from .exporters.markdown_exporter import export_markdown
from .exporters.text_exporter import export_text
from .fetcher import Fetcher
from .models import ScrapeResult
from .parser import parse_cpu_page

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scrape Oracle Critical Patch Update pages for CVE data.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable HTTP cache (re-fetch all pages)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data",
        help="Output directory for generated files (default: data)",
    )
    parser.add_argument(
        "--skip-java-se",
        action="store_true",
        help="Skip Java SE-specific CPU pages",
    )
    parser.add_argument(
        "--only-recent",
        type=int,
        default=0,
        metavar="N",
        help="Only scrape the N most recent CPUs (0=all)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    """Main orchestrator. Returns exit code."""
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    output_dir = Path(args.output_dir)

    logger.info("Starting Oracle CPU CVE scraper")

    # Initialize fetcher
    fetcher = Fetcher(use_cache=not args.no_cache)

    # Discover CPU releases
    releases = discover_cpu_releases(fetcher)
    logger.info("Discovered %d CPU releases", len(releases))

    # Filter
    if args.skip_java_se:
        releases = [r for r in releases if not r.is_java_se]
        logger.info("After filtering Java SE: %d releases", len(releases))

    if args.only_recent > 0:
        releases = releases[-args.only_recent:]
        logger.info("Limited to %d most recent releases", len(releases))

    # Fetch and parse each CPU page
    succeeded = 0
    failed = 0
    errors = []

    for i, release in enumerate(releases, 1):
        logger.info("[%d/%d] Processing %s", i, len(releases), release.label)

        # For the most recent CPU, always skip cache to get latest revisions
        is_latest = (i == len(releases))
        html = fetcher.fetch(release.url, skip_cache=is_latest)

        if html is None:
            error_msg = f"Failed to fetch {release.label} ({release.url})"
            release.error = error_msg
            errors.append(error_msg)
            failed += 1
            logger.error(error_msg)
            continue

        try:
            entries = parse_cpu_page(html, release)
            release.cve_entries = entries
            succeeded += 1
        except Exception as e:
            error_msg = f"Failed to parse {release.label}: {e}"
            release.error = error_msg
            errors.append(error_msg)
            failed += 1
            logger.error(error_msg, exc_info=args.verbose)

    # Build result
    total_cves = sum(len(r.cve_entries) for r in releases)
    unique_ids = set()
    for r in releases:
        for e in r.cve_entries:
            unique_ids.add(e.cve_id)

    result = ScrapeResult(
        cpu_releases=releases,
        total_cves=total_cves,
        unique_cve_ids=len(unique_ids),
        total_cpus_scraped=succeeded,
        total_cpus_failed=failed,
        errors=errors,
        scrape_timestamp=timestamp,
    )

    logger.info(
        "Scraping complete: %d CPUs scraped, %d failed, %d total CVEs, %d unique",
        succeeded, failed, total_cves, len(unique_ids),
    )

    # Export
    export_text(result, output_dir / "cves.txt")
    export_csv(result, output_dir / "cves.csv")
    export_json(result, output_dir / "cves.json")
    export_markdown(result, output_dir / "summary.md")

    logger.info("Output written to %s/", output_dir)

    # Exit code: 0 if any succeeded, 1 if all failed
    if succeeded == 0 and len(releases) > 0:
        logger.error("All CPU pages failed to process")
        return 1
    return 0


def main() -> None:
    args = parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
