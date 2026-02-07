"""HTTP client with retry, rate-limiting, and file-based caching."""

from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path

import requests

from .constants import (
    MAX_RETRIES,
    RATE_LIMIT_DELAY,
    REQUEST_TIMEOUT,
    RETRY_BACKOFF_BASE,
    USER_AGENT,
)

logger = logging.getLogger(__name__)


class Fetcher:
    """HTTP fetcher with caching, retries, and rate limiting."""

    def __init__(self, cache_dir: str = "cache", use_cache: bool = True):
        self.cache_dir = Path(cache_dir)
        self.use_cache = use_cache
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self._last_request_time: float = 0

        if self.use_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, url: str) -> Path:
        """Get cache file path for a URL."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        # Use a readable filename component
        safe_name = url.rsplit("/", 1)[-1].replace(".html", "")
        return self.cache_dir / f"{safe_name}_{url_hash}.html"

    def _rate_limit(self) -> None:
        """Enforce delay between requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)

    def fetch(self, url: str, skip_cache: bool = False) -> str | None:
        """Fetch a URL, using cache if available.

        Returns HTML content as string, or None on failure.
        """
        # Check cache first
        if self.use_cache and not skip_cache:
            cache_file = self._cache_path(url)
            if cache_file.exists():
                logger.debug("Cache hit: %s", url)
                return cache_file.read_text(encoding="utf-8")

        # Rate limit
        self._rate_limit()

        # Fetch with retries
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                logger.info("Fetching: %s (attempt %d/%d)", url, attempt + 1, MAX_RETRIES)
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                self._last_request_time = time.time()

                if response.status_code == 200:
                    html = response.text
                    # Cache successful response
                    if self.use_cache:
                        cache_file = self._cache_path(url)
                        cache_file.write_text(html, encoding="utf-8")
                    return html

                if response.status_code >= 400 and response.status_code < 500:
                    # Don't retry client errors
                    logger.error("Client error %d for %s", response.status_code, url)
                    return None

                # Server error - retry
                last_error = f"HTTP {response.status_code}"
                logger.warning("Server error %d for %s, retrying...", response.status_code, url)

            except requests.RequestException as e:
                last_error = str(e)
                logger.warning("Request failed for %s: %s, retrying...", url, e)
                self._last_request_time = time.time()

            if attempt < MAX_RETRIES - 1:
                backoff = RETRY_BACKOFF_BASE ** attempt
                logger.debug("Backoff: %ds", backoff)
                time.sleep(backoff)

        logger.error("All retries failed for %s: %s", url, last_error)
        return None
