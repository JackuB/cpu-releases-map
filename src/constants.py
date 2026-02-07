"""Constants and configuration for the Oracle CPU CVE scraper."""

BASE_URL = "https://www.oracle.com"
INDEX_URL = f"{BASE_URL}/security-alerts/"
ARCHIVE_URL = f"{BASE_URL}/security-alerts/cpuarchive.html"

# Month abbreviations used in Oracle CPU URLs -> quarter mapping
MONTH_TO_QUARTER = {
    "jan": "Q1",
    "feb": "Q1",
    "mar": "Q1",
    "apr": "Q2",
    "may": "Q2",
    "jun": "Q2",
    "jul": "Q3",
    "aug": "Q3",
    "sep": "Q3",
    "oct": "Q4",
    "nov": "Q4",
    "dec": "Q4",
}

# Some Oracle URLs use full month names (e.g., cpujuly2011)
MONTH_FULL_TO_ABBR = {
    "january": "jan",
    "february": "feb",
    "march": "mar",
    "april": "apr",
    "july": "jul",
    "june": "jun",
    "october": "oct",
}

# Oracle uses inconsistent column header text across CPU pages.
# This maps all known variations to canonical field names.
HEADER_ALIASES = {
    # CVE identifier
    "cve#": "cve_id",
    "cve id": "cve_id",
    "cve": "cve_id",
    # Component / sub-component
    "component": "component",
    "sub\u00adcomponent": "component",
    "sub-component": "component",
    "subcomponent": "component",
    # Package / privilege
    "package and/or privilege required": "package_privilege",
    "package and/or\nprivilege required": "package_privilege",
    "package and/or privilege\nrequired": "package_privilege",
    "privilege required": "package_privilege",
    # Protocol
    "protocol": "protocol",
    # Remote exploit
    "remote exploit without auth.?": "remote_exploit",
    "remote\nexploit\nwithout\nauth.?": "remote_exploit",
    "remote exploit without auth?": "remote_exploit",
    "remote exploitwithout auth.?": "remote_exploit",
    "remote exploit without auth.": "remote_exploit",
    # CVSS 3.x fields
    "base score": "base_score",
    "basescore": "base_score",
    "attack vector": "attack_vector",
    "attackvector": "attack_vector",
    "attack complex": "attack_complexity",
    "attackcomplex": "attack_complexity",
    "attack complexity": "attack_complexity",
    "privs req'd": "privileges_required",
    "privsreq'd": "privileges_required",
    "privileges required": "privileges_required",
    "user interact": "user_interaction",
    "userinteract": "user_interaction",
    "user interaction": "user_interaction",
    "scope": "scope",
    "confid-\nentiality": "confidentiality",
    "confid- entiality": "confidentiality",
    "confidentiality": "confidentiality",
    "confid-entiality": "confidentiality",
    "integrity": "integrity",
    "inte-grity": "integrity",
    "inte- grity": "integrity",
    "availability": "availability",
    "avail-ability": "availability",
    "avail- ability": "availability",
    # CVSS 2.0 fields
    "access vector": "access_vector",
    "access complexity": "access_complexity",
    "authentication": "authentication",
    "auth.": "authentication",
    # Versions / notes
    "supported versions affected": "affected_versions",
    "supported\nversions\naffected": "affected_versions",
    "supportedversions affected": "affected_versions",
    "notes": "notes",
}

# HTTP client configuration
RATE_LIMIT_DELAY = 1.5  # seconds between requests
REQUEST_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # exponential backoff: 1s, 2s, 4s

USER_AGENT = (
    "OracleCPU-CVE-Scraper/1.0 "
    "(https://github.com/cpu-releases-map; security-research)"
)
