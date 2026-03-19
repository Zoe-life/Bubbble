"""
Phase 1 — VirusTotal API v3 Integration

Submits a URL to VirusTotal for analysis against 70+ antivirus engines
and URL-reputation scanners. Results are cached by URL hash to avoid
redundant API calls and to stay within rate limits.

Docs: https://developers.virustotal.com/reference/url-object
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class VTStats:
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0


@dataclass
class VirusTotalResult:
    url: str
    scan_id: str
    stats: VTStats = field(default_factory=VTStats)
    categories: dict[str, str] = field(default_factory=dict)
    permalink: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.stats.malicious > 0 or self.stats.suspicious >= 3

    @property
    def detection_ratio(self) -> str:
        total = (
            self.stats.malicious
            + self.stats.suspicious
            + self.stats.undetected
            + self.stats.harmless
        )
        return f"{self.stats.malicious}/{total}" if total else "0/0"


def _url_id(url: str) -> str:
    """VirusTotal URL identifier: URL-safe base64 of the raw URL (no padding)."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


class VirusTotalChecker:
    """
    Async client for the VirusTotal URL scanning API v3.

    Usage::

        checker = VirusTotalChecker()
        async with checker:
            result = await checker.check_url("https://evil.example.com")
            if result and result.is_malicious:
                print(result.detection_ratio)
    """

    def __init__(self, api_key: str = VIRUSTOTAL_API_KEY) -> None:
        if not api_key:
            logger.warning(
                "VIRUSTOTAL_API_KEY not set — VirusTotal checks will be skipped."
            )
        self._api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "VirusTotalChecker":
        self._session = aiohttp.ClientSession(
            headers={
                "x-apikey": self._api_key,
                "Accept": "application/json",
            }
        )
        return self

    async def __aexit__(self, *_) -> None:
        if self._session:
            await self._session.close()

    async def check_url(self, url: str) -> Optional[VirusTotalResult]:
        """
        Check a URL against VirusTotal.
        First attempts to retrieve an existing report; if none exists, submits
        for scanning and returns the pending result with whatever stats are
        already available (async scanning continues server-side).
        """
        if not self._api_key:
            return None

        url_id = _url_id(url)

        # 1. Try to fetch existing analysis
        existing = await self._get_report(url_id)
        if existing:
            return existing

        # 2. Submit for scan
        scan_id = await self._submit_url(url)
        if not scan_id:
            return None

        # 3. Return partial (may not have results yet — caller can poll later)
        return VirusTotalResult(url=url, scan_id=scan_id)

    async def _get_report(self, url_id: str) -> Optional[VirusTotalResult]:
        try:
            async with self._session.get(
                f"{VT_BASE}/urls/{url_id}",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 404:
                    return None
                resp.raise_for_status()
                data = (await resp.json()).get("data", {})
                return self._parse_report(data)
        except Exception as exc:
            logger.error("VirusTotal get_report error: %s", exc)
            return None

    async def _submit_url(self, url: str) -> Optional[str]:
        try:
            async with self._session.post(
                f"{VT_BASE}/urls",
                data={"url": url},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return data.get("data", {}).get("id", "")
        except Exception as exc:
            logger.error("VirusTotal submit error: %s", exc)
            return None

    @staticmethod
    def _parse_report(data: dict) -> VirusTotalResult:
        attrs = data.get("attributes", {})
        raw_stats = attrs.get("last_analysis_stats", {})
        stats = VTStats(
            malicious=raw_stats.get("malicious", 0),
            suspicious=raw_stats.get("suspicious", 0),
            undetected=raw_stats.get("undetected", 0),
            harmless=raw_stats.get("harmless", 0),
            timeout=raw_stats.get("timeout", 0),
        )
        return VirusTotalResult(
            url=attrs.get("url", ""),
            scan_id=data.get("id", ""),
            stats=stats,
            categories=attrs.get("categories", {}),
            permalink=f"https://www.virustotal.com/gui/url/{data.get('id', '')}",
        )
