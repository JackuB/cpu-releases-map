# cpu-releases-map

Structured data of Oracle Critical Patch Update (CPU) releases. Scrapes ~65 quarterly CPU advisory pages (2010-2026) and extracts CVE data from risk matrix tables into machine-readable formats.

## Usage

```bash
pip install -r requirements.txt
python -m src.main --verbose
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--verbose` | Enable debug logging |
| `--no-cache` | Disable HTTP cache (re-fetch all pages) |
| `--output-dir DIR` | Output directory (default: `data/`) |
| `--skip-java-se` | Skip Java SE-specific CPU pages |
| `--only-recent N` | Only scrape the N most recent CPUs |

### Examples

```bash
# Scrape everything
python -m src.main

# Scrape only the 3 most recent CPUs
python -m src.main --only-recent 3 --verbose

# Fresh scrape, no cache
python -m src.main --no-cache
```

## Output Files

All output is written to `data/`:

| File | Format | Description |
|------|--------|-------------|
| `cves.txt` | Plain text | Unique CVE IDs, one per line, sorted |
| `cves.csv` | CSV | One row per CVE appearance with full metadata |
| `cves.json` | JSON | Structured data grouped by CPU release and product family |
| `summary.md` | Markdown | Human-readable overview with stats and per-CPU breakdown |

## Automation

A GitHub Actions workflow (`.github/workflows/update-cve-data.yml`) runs automatically after each quarterly Oracle CPU release:

- **Day after release** (18th of Jan/Apr/Jul/Oct)
- **One week later** to catch Rev 2 updates
- **Following month** as a safety net

Can also be triggered manually via `workflow_dispatch`.

## How It Works

1. **Discovery**: Fetches Oracle's security alerts index and archive pages to find all CPU advisory URLs
2. **Fetching**: Downloads each CPU page with rate limiting, retries, and local file caching
3. **Parsing**: Extracts CVE data from HTML risk matrix tables, handling CVSS 2.0, 3.0, and 3.1 column formats
4. **Export**: Writes structured data in four formats
