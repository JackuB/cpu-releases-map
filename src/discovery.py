"""Discovers CPU release page URLs from Oracle's index and archive pages."""

from __future__ import annotations

import logging
import re

from bs4 import BeautifulSoup

from .constants import BASE_URL, ARCHIVE_URL, INDEX_URL, MONTH_FULL_TO_ABBR, MONTH_TO_QUARTER
from .fetcher import Fetcher
from .models import CPURelease

logger = logging.getLogger(__name__)

# Matches URLs like /security-alerts/cpujan2026.html, /security-alerts/javacpufeb2013.html,
# or /security-alerts/cspumay2026.html (Oracle's monthly Critical Security Patch Update,
# introduced May 2026 to fill the months between quarterly CPUs).
CPU_URL_PATTERN = re.compile(
    r"/security-alerts/(java)?(cpu|cspu)([a-z]+)(\d{4})(v\d+|update)?\.html",
    re.IGNORECASE,
)


def _parse_cpu_url(url: str) -> CPURelease | None:
    """Parse a CPU/CSPU URL into a CPURelease shell."""
    match = CPU_URL_PATTERN.search(url)
    if not match:
        return None

    is_java = match.group(1) is not None
    release_type = match.group(2).upper()
    month_raw = match.group(3).lower()
    year = int(match.group(4))

    # Normalize full month names to abbreviations
    month = MONTH_FULL_TO_ABBR.get(month_raw, month_raw)

    if month not in MONTH_TO_QUARTER:
        logger.warning("Unknown month '%s' in URL: %s", month_raw, url)
        return None

    quarter = f"{year}-{MONTH_TO_QUARTER[month]}"

    # Build full URL if relative
    if url.startswith("/"):
        full_url = BASE_URL + url
    elif not url.startswith("http"):
        full_url = BASE_URL + "/" + url
    else:
        full_url = url

    label_prefix = "Java SE " if is_java else ""
    label = f"{label_prefix}{release_type} {month.capitalize()} {year}"

    return CPURelease(
        url=full_url,
        label=label,
        month=month,
        year=year,
        quarter=quarter,
        is_java_se=is_java,
        release_type=release_type,
    )


def _extract_cpu_links(html: str) -> list[str]:
    """Extract CPU-related links from an HTML page."""
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if CPU_URL_PATTERN.search(href):
            links.append(href)
    return links


def discover_cpu_releases(fetcher: Fetcher) -> list[CPURelease]:
    """Discover all CPU release pages from index and archive.

    Returns a deduplicated, chronologically sorted list of CPURelease objects.
    """
    all_urls: set[str] = set()
    releases: dict[str, CPURelease] = {}

    # Fetch both index pages (always skip cache for latest data)
    for page_url in [INDEX_URL, ARCHIVE_URL]:
        html = fetcher.fetch(page_url, skip_cache=True)
        if not html:
            logger.error("Failed to fetch %s", page_url)
            continue

        links = _extract_cpu_links(html)
        logger.info("Found %d CPU links on %s", len(links), page_url)

        for link in links:
            # Normalize to full URL for deduplication
            if link.startswith("/"):
                full_url = BASE_URL + link
            elif not link.startswith("http"):
                full_url = BASE_URL + "/" + link
            else:
                full_url = link

            if full_url in all_urls:
                continue
            all_urls.add(full_url)

            release = _parse_cpu_url(link)
            if release:
                releases[full_url] = release

    # Sort chronologically (oldest first)
    sorted_releases = sorted(
        releases.values(),
        key=lambda r: (r.year, list(MONTH_TO_QUARTER.keys()).index(r.month) if r.month in MONTH_TO_QUARTER else 0),
    )

    logger.info("Discovered %d unique CPU releases", len(sorted_releases))
    return sorted_releases
