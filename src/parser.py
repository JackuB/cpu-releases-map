"""HTML parsing of Oracle CPU risk matrix tables."""

from __future__ import annotations

import logging
import re

from bs4 import BeautifulSoup, Tag

from .constants import HEADER_ALIASES
from .models import CPURelease, CVEEntry

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
CVSS_VERSION_PATTERN = re.compile(r"CVSS\s+VERSION\s+(\d+\.\d+)", re.IGNORECASE)


def _normalize_header(text: str) -> str:
    """Normalize a header cell's text for alias lookup."""
    # Collapse whitespace, soft hyphens, newlines
    text = text.replace("\u00ad", "").replace("\xa0", " ")
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def _get_cell_text(cell: Tag) -> str:
    """Extract clean text from a table cell."""
    # Get text, handling <br> tags as space separators
    for br in cell.find_all("br"):
        br.replace_with(" ")
    text = cell.get_text(separator=" ", strip=True)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _find_product_family(table: Tag) -> str:
    """Find the product family name from the nearest heading before a table."""
    # Walk backward through previous siblings and parents to find a heading
    for tag in _preceding_tags(table):
        if tag.name in ("h2", "h3", "h4", "h5"):
            text = tag.get_text(strip=True)
            # Clean up common suffixes
            text = re.sub(r"\s*Risk\s*Matrix\s*$", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*Executive\s*Summary\s*$", "", text, flags=re.IGNORECASE)
            if text:
                return text
    return "Unknown"


def _preceding_tags(element: Tag):
    """Yield tags preceding the given element in document order."""
    current = element
    while current:
        sibling = current.previous_sibling
        while sibling:
            if isinstance(sibling, Tag):
                yield sibling
            sibling = sibling.previous_sibling
        current = current.parent
        if current and isinstance(current, Tag):
            # Don't yield the parent itself unless it's a heading
            if current.name in ("h2", "h3", "h4", "h5"):
                yield current


def _detect_cvss_version(table: Tag) -> str:
    """Detect the CVSS version from table header text."""
    # Only check true header rows to avoid scanning all CVE ID sticky <th>s
    header_text = ""
    for tr in table.find_all("tr"):
        if _is_header_row(tr):
            for th in tr.find_all("th"):
                header_text += " " + th.get_text()
        else:
            break

    match = CVSS_VERSION_PATTERN.search(header_text)
    if match:
        return match.group(1)

    # Heuristic: check for CVSS 2.0-specific columns
    normalized = header_text.lower()
    if "access vector" in normalized or "authentication" in normalized:
        return "2.0"
    if "attack vector" in normalized or "privs req" in normalized:
        return "3.1"

    return "unknown"


def _is_risk_matrix_table(table: Tag) -> bool:
    """Check if a table is a risk matrix (contains CVE data)."""
    first_row = table.find("tr")
    if not first_row:
        return False

    headers = first_row.find_all("th")
    if not headers:
        return False

    # Check if any header contains "CVE"
    for th in headers:
        text = th.get_text(strip=True).upper()
        if "CVE" in text:
            return True

    return False


def _is_header_row(tr: Tag) -> bool:
    """Determine if a row is a true header row vs a data row with a sticky <th>.

    Oracle uses <th class="otable-col-sticky"> for CVE IDs in data rows.
    True header rows either have no <td> cells at all, or have multiple <th>
    with colspan/rowspan attributes.
    """
    tds = tr.find_all("td")
    ths = tr.find_all("th")
    if not ths:
        return False
    # If there are no <td> cells, it's a header row
    if not tds:
        return True
    # If there's exactly one <th> and multiple <td>, it's a data row with sticky CVE column
    if len(ths) == 1 and len(tds) > 1:
        return False
    return True


def _build_column_map(table: Tag) -> dict[str, int]:
    """Build a mapping from canonical field names to column indices.

    Handles multi-row headers with colspan for CVSS sub-columns.
    """
    column_map: dict[str, int] = {}
    header_rows = []

    # Collect true header rows (not data rows with sticky CVE <th>)
    for tr in table.find_all("tr"):
        if _is_header_row(tr):
            header_rows.append(tr)
        else:
            break  # Stop at first data row

    if not header_rows:
        return column_map

    # For simple single-row headers
    if len(header_rows) == 1:
        for idx, th in enumerate(header_rows[0].find_all("th")):
            text = _normalize_header(th.get_text())
            canonical = HEADER_ALIASES.get(text)
            if canonical:
                column_map[canonical] = idx
        return column_map

    # Multi-row header handling
    # First pass: build a flat list of column positions
    # Row 1 has parent headers (some with colspan), row 2 has sub-headers
    first_row_ths = header_rows[0].find_all("th")
    second_row_ths = header_rows[1].find_all("th") if len(header_rows) > 1 else []

    col_idx = 0
    sub_header_idx = 0

    for th in first_row_ths:
        colspan = int(th.get("colspan", 1))
        rowspan = int(th.get("rowspan", 1))
        text = _normalize_header(th.get_text())

        if colspan > 1:
            # This is a parent header spanning sub-columns (e.g., "CVSS VERSION 3.1 RISK")
            # The sub-headers in the next row fill these positions
            for i in range(colspan):
                if sub_header_idx < len(second_row_ths):
                    sub_text = _normalize_header(second_row_ths[sub_header_idx].get_text())
                    canonical = HEADER_ALIASES.get(sub_text)
                    if canonical:
                        column_map[canonical] = col_idx + i
                    sub_header_idx += 1
            col_idx += colspan
        else:
            # Regular header spanning both rows (rowspan=2 typically)
            canonical = HEADER_ALIASES.get(text)
            if canonical:
                column_map[canonical] = col_idx
            col_idx += 1

    return column_map


def _parse_table(table: Tag, cpu_release: CPURelease, product_family: str, cvss_version: str) -> list[CVEEntry]:
    """Parse a single risk matrix table into CVEEntry objects."""
    column_map = _build_column_map(table)

    if "cve_id" not in column_map:
        logger.warning("No CVE column found in table for %s", product_family)
        return []

    logger.debug("Column map for %s: %s", product_family, column_map)

    entries = []
    # Process data rows (skip true header rows)
    for tr in table.find_all("tr"):
        if _is_header_row(tr):
            continue

        # Collect all cells: <th> (sticky CVE column) + <td> in document order
        cells = tr.find_all(["th", "td"])
        if not cells:
            continue

        # Get CVE ID from the mapped column
        cve_col = column_map.get("cve_id", 0)
        if cve_col >= len(cells):
            continue

        cve_text = _get_cell_text(cells[cve_col])

        # Validate CVE ID format
        cve_match = CVE_PATTERN.search(cve_text)
        if not cve_match:
            continue

        cve_id = cve_match.group(0)

        # Build entry from mapped columns
        def get_field(field_name: str) -> str:
            idx = column_map.get(field_name)
            if idx is not None and idx < len(cells):
                return _get_cell_text(cells[idx])
            return ""

        entry = CVEEntry(
            cve_id=cve_id,
            cpu_quarter=cpu_release.quarter,
            cpu_url=cpu_release.url,
            product_family=product_family,
            cvss_version=cvss_version,
            component=get_field("component"),
            base_score=get_field("base_score"),
            attack_vector=get_field("attack_vector"),
            attack_complexity=get_field("attack_complexity"),
            privileges_required=get_field("privileges_required"),
            user_interaction=get_field("user_interaction"),
            scope=get_field("scope"),
            confidentiality=get_field("confidentiality"),
            integrity=get_field("integrity"),
            availability=get_field("availability"),
            access_vector=get_field("access_vector") or None,
            access_complexity=get_field("access_complexity") or None,
            authentication=get_field("authentication") or None,
            package_privilege=get_field("package_privilege"),
            protocol=get_field("protocol"),
            remote_exploit=get_field("remote_exploit"),
            affected_versions=get_field("affected_versions"),
            notes=get_field("notes"),
        )
        entries.append(entry)

    return entries


def parse_cpu_page(html: str, cpu_release: CPURelease) -> list[CVEEntry]:
    """Parse all risk matrix tables from a CPU page.

    Returns a list of CVEEntry objects found on the page.
    """
    soup = BeautifulSoup(html, "html.parser")
    all_entries: list[CVEEntry] = []

    tables = soup.find_all("table")
    risk_tables_found = 0

    for table in tables:
        if not _is_risk_matrix_table(table):
            continue

        risk_tables_found += 1
        product_family = _find_product_family(table)
        cvss_version = _detect_cvss_version(table)

        logger.debug(
            "Parsing risk matrix: %s (CVSS %s) from %s",
            product_family,
            cvss_version,
            cpu_release.label,
        )

        entries = _parse_table(table, cpu_release, product_family, cvss_version)
        all_entries.extend(entries)

        logger.debug("  Found %d CVEs in %s", len(entries), product_family)

    if risk_tables_found == 0:
        logger.warning("No risk matrix tables found on %s", cpu_release.url)
    else:
        logger.info(
            "Parsed %d CVEs from %d tables on %s",
            len(all_entries),
            risk_tables_found,
            cpu_release.label,
        )

    return all_entries
