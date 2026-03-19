"""
Phase 1 — Google Safe Browsing API v4 Integration

Checks URLs against Google's Safe Browsing threat lists using the
Lookup API v4 endpoint. Supports all threat types: MALWARE, SOCIAL_ENGINEERING
(phishing), UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION, and
MALICIOUS_BINARY.

Docs: https://developers.google.com/safe-browsing/v4/lookup-api
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

SAFE_BROWSING_API_KEY: str = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
LOOKUP_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
    "MALICIOUS_BINARY",
]
PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]


@dataclass
class SafeBrowsingHit:
    """Returned when a URL matches a Safe Browsing threat list."""

    url: str
    threat_type: str        # e.g. "SOCIAL_ENGINEERING"
    platform_type: str      # e.g. "ANY_PLATFORM"
    threat_entry_type: str  # e.g. "URL"


class GoogleSafeBrowsingChecker:
    """
    Async wrapper for the Google Safe Browsing Lookup API v4.

    Usage::

        checker = GoogleSafeBrowsingChecker()
        async with checker:
            hits = await checker.check_urls(["https://evil.example.com"])
    """

    def __init__(self, api_key: str = SAFE_BROWSING_API_KEY) -> None:
        if not api_key:
            logger.warning(
                "GOOGLE_SAFE_BROWSING_API_KEY not set — Safe Browsing checks will be skipped."
            )
        self._api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "GoogleSafeBrowsingChecker":
        self._session = aiohttp.ClientSession(
            headers={"Content-Type": "application/json"}
        )
        return self

    async def __aexit__(self, *_) -> None:
        if self._session:
            await self._session.close()

    async def check_url(self, url: str) -> Optional[SafeBrowsingHit]:
        """Check a single URL. Returns a SafeBrowsingHit or None."""
        results = await self.check_urls([url])
        return results[0] if results else None

    async def check_urls(self, urls: list[str]) -> list[SafeBrowsingHit]:
        """
        Check up to 500 URLs in a single API call.
        Returns one SafeBrowsingHit per matched URL (de-duplicated by URL).
        """
        if not self._api_key or not urls:
            return []

        payload = {
            "client": {"clientId": "bubbble", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": PLATFORM_TYPES,
                "threatEntryTypes": THREAT_ENTRY_TYPES,
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        endpoint = f"{LOOKUP_ENDPOINT}?key={self._api_key}"

        try:
            async with self._session.post(
                endpoint,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
        except Exception as exc:
            logger.error("Safe Browsing API error: %s", exc)
            return []

        matches = data.get("matches", [])
        seen: set[str] = set()
        hits: list[SafeBrowsingHit] = []
        for m in matches:
            match_url = m.get("threat", {}).get("url", "")
            if match_url and match_url not in seen:
                seen.add(match_url)
                hits.append(
                    SafeBrowsingHit(
                        url=match_url,
                        threat_type=m.get("threatType", ""),
                        platform_type=m.get("platformType", ""),
                        threat_entry_type=m.get("threatEntryType", ""),
                    )
                )
        logger.info(
            "Safe Browsing: checked %d URL(s), %d hit(s)", len(urls), len(hits)
        )
        return hits
