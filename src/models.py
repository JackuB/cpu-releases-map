"""Data models for Oracle CPU CVE scraper."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVEEntry:
    """A single CVE entry from a risk matrix table."""

    cve_id: str
    cpu_quarter: str  # e.g., "2026-Q1"
    cpu_url: str
    product_family: str
    component: str = ""
    cvss_version: str = ""  # "3.1", "3.0", "2.0"
    base_score: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""
    # CVSS 2.0-only fields
    access_vector: Optional[str] = None
    access_complexity: Optional[str] = None
    authentication: Optional[str] = None
    # Other fields
    package_privilege: str = ""
    protocol: str = ""
    remote_exploit: str = ""
    affected_versions: str = ""
    notes: str = ""


@dataclass
class CPURelease:
    """Represents a single CPU release page."""

    url: str
    label: str
    month: str  # e.g., "jan"
    year: int
    quarter: str  # e.g., "2026-Q1"
    is_java_se: bool = False
    cve_entries: list[CVEEntry] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class ScrapeResult:
    """Aggregated result of the entire scrape run."""

    cpu_releases: list[CPURelease] = field(default_factory=list)
    total_cves: int = 0
    unique_cve_ids: int = 0
    total_cpus_scraped: int = 0
    total_cpus_failed: int = 0
    errors: list[str] = field(default_factory=list)
    scrape_timestamp: str = ""
