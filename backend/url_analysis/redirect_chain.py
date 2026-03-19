"""
Phase 1 — Redirect-Chain Unwinding

Follows all HTTP redirects for a URL (301, 302, 307, 308, meta-refresh, etc.)
and returns the full hop chain. This is critical because phishing links almost
always pass through URL shorteners or redirect services before reaching the
malicious destination.

The final resolved URL is the one scored by the risk engine.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp

logger = logging.getLogger(__name__)

MAX_HOPS = 15               # Abort after this many redirects
CONNECT_TIMEOUT = 8         # seconds per hop
REQUEST_TIMEOUT = 12        # total per-request timeout
MAX_BODY_BYTES = 32_768     # read up to 32 KB for meta-refresh detection

# Matches <meta http-equiv="refresh" content="0; url=https://...">
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>\s]+)',
    re.IGNORECASE,
)


@dataclass
class Hop:
    url: str
    status_code: Optional[int] = None
    redirect_type: str = ""   # "http_header" | "meta_refresh" | "final"


@dataclass
class RedirectChainResult:
    original_url: str
    final_url: str
    hops: list[Hop] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def chain_length(self) -> int:
        return len(self.hops)

    @property
    def crossed_domains(self) -> list[str]:
        """Returns distinct domains visited during the redirect chain."""
        seen: list[str] = []
        for hop in self.hops:
            domain = urlparse(hop.url).netloc
            if domain and (not seen or seen[-1] != domain):
                seen.append(domain)
        return seen


async def unwind_redirects(url: str) -> RedirectChainResult:
    """
    Follow all redirects for *url* and return the full chain.
    Does NOT visit the final URL with a headless browser — that happens in
    content_preview.py.
    """
    hops: list[Hop] = []
    current_url = url
    connector = aiohttp.TCPConnector(ssl=False)  # skip SSL errors; ssl_check.py handles validation

    try:
        async with aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": "Bubbble-Scanner/1.0"},
        ) as session:
            for _ in range(MAX_HOPS):
                hop = Hop(url=current_url)
                hops.append(hop)

                try:
                    async with session.get(
                        current_url,
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(
                            connect=CONNECT_TIMEOUT, total=REQUEST_TIMEOUT
                        ),
                    ) as resp:
                        hop.status_code = resp.status

                        # HTTP header redirect
                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get("Location", "")
                            if location:
                                hop.redirect_type = "http_header"
                                current_url = urljoin(current_url, location)
                                continue

                        # Check for meta-refresh in HTML body
                        if "text/html" in resp.content_type:
                            body = await resp.content.read(MAX_BODY_BYTES)
                            match = _META_REFRESH_RE.search(body.decode("utf-8", errors="ignore"))
                            if match:
                                hop.redirect_type = "meta_refresh"
                                current_url = urljoin(current_url, match.group(1))
                                continue

                        # No redirect — this is the final destination
                        hop.redirect_type = "final"
                        break

                except aiohttp.ClientError as exc:
                    hop.redirect_type = "error"
                    logger.warning("Redirect error at %s: %s", current_url, exc)
                    return RedirectChainResult(
                        original_url=url,
                        final_url=current_url,
                        hops=hops,
                        error=str(exc),
                    )
            else:
                logger.warning("Max hops (%d) reached for %s", MAX_HOPS, url)

    except Exception as exc:
        logger.error("redirect chain unwind failed: %s", exc)
        return RedirectChainResult(
            original_url=url,
            final_url=current_url,
            hops=hops,
            error=str(exc),
        )

    final_url = hops[-1].url if hops else url
    logger.info(
        "Redirect chain for %s: %d hop(s) → %s", url, len(hops), final_url
    )
    return RedirectChainResult(
        original_url=url,
        final_url=final_url,
        hops=hops,
    )
