"""
Phase 1 — MISP + abuse.ch Feed Subscription

Fetches threat intelligence indicators from:
  1. abuse.ch URLhaus — active malware URLs (CSV)
  2. abuse.ch FeodoTracker — botnet C2 IP blocklist (CSV)
  3. MISP OSINT feed — JSON MISP format (configurable URL)

All indicators are written into the LocalBlocklistCache, which is then
consulted on every link scan before hitting external APIs.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from backend.threat_intel.local_blocklist import LocalBlocklistCache

logger = logging.getLogger(__name__)

# ── Feed URLs ────────────────────────────────────────────────────────────────

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"
FEODOTRACKER_CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

# Set MISP_FEED_URL to a MISP server feed endpoint (OSINT format)
MISP_FEED_URL: str = os.environ.get("MISP_FEED_URL", "")
MISP_AUTH_KEY: str = os.environ.get("MISP_AUTH_KEY", "")


@dataclass
class FeedRefreshSummary:
    source: str
    domains_added: int = 0
    ips_added: int = 0
    error: Optional[str] = None


# ── URLhaus (malware URLs) ───────────────────────────────────────────────────

async def fetch_urlhaus(
    session: aiohttp.ClientSession,
    cache: LocalBlocklistCache,
) -> FeedRefreshSummary:
    """
    Download URLhaus online-URL CSV and extract unique domains for the blocklist.
    CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    """
    summary = FeedRefreshSummary(source="abusech_urlhaus")
    try:
        async with session.get(
            URLHAUS_CSV_URL, timeout=aiohttp.ClientTimeout(total=60)
        ) as resp:
            resp.raise_for_status()
            text = await resp.text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        summary.error = str(exc)
        logger.error("URLhaus fetch error: %s", exc)
        return summary

    domains: list[str] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 3:
            continue
        raw_url = row[2].strip()
        try:
            host = urlparse(raw_url).hostname or ""
            if host:
                domains.append(host)
        except Exception:
            pass

    unique_domains = list(set(domains))
    summary.domains_added = await cache.add_domains(unique_domains, "abusech_urlhaus")
    logger.info("URLhaus: %d unique domains added", summary.domains_added)
    return summary


# ── FeodoTracker (C2 IPs) ────────────────────────────────────────────────────

async def fetch_feodotracker(
    session: aiohttp.ClientSession,
    cache: LocalBlocklistCache,
) -> FeedRefreshSummary:
    """
    Download FeodoTracker IP blocklist CSV and populate the IP blocklist.
    CSV columns: first_seen, dst_ip, dst_port, c2_status, last_online, malware
    """
    summary = FeedRefreshSummary(source="abusech_feodotracker")
    try:
        async with session.get(
            FEODOTRACKER_CSV_URL, timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            resp.raise_for_status()
            text = await resp.text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        summary.error = str(exc)
        logger.error("FeodoTracker fetch error: %s", exc)
        return summary

    ips: list[str] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 2:
            continue
        ip = row[1].strip()
        if ip:
            ips.append(ip)

    unique_ips = list(set(ips))
    summary.ips_added = await cache.add_ips(unique_ips, "abusech_feodotracker")
    logger.info("FeodoTracker: %d unique IPs added", summary.ips_added)
    return summary


# ── MISP OSINT Feed ──────────────────────────────────────────────────────────

async def fetch_misp_feed(
    session: aiohttp.ClientSession,
    cache: LocalBlocklistCache,
) -> FeedRefreshSummary:
    """
    Fetch a MISP JSON feed and extract domain and IP attributes.
    Supports the MISP OSINT event JSON format.
    """
    summary = FeedRefreshSummary(source="misp")
    if not MISP_FEED_URL:
        summary.error = "MISP_FEED_URL not configured"
        return summary

    headers = {}
    if MISP_AUTH_KEY:
        headers["Authorization"] = MISP_AUTH_KEY

    try:
        async with session.get(
            MISP_FEED_URL,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=60),
        ) as resp:
            resp.raise_for_status()
            data = await resp.json(content_type=None)
    except Exception as exc:
        summary.error = str(exc)
        logger.error("MISP feed fetch error: %s", exc)
        return summary

    domains: list[str] = []
    ips: list[str] = []

    # Handle both single event and list of events
    events = data if isinstance(data, list) else [data]
    for event in events:
        for attr in event.get("Event", {}).get("Attribute", []):
            attr_type = attr.get("type", "")
            value = attr.get("value", "").strip()
            if not value:
                continue
            if attr_type in ("domain", "hostname", "domain|ip"):
                domains.append(value.split("|")[0])
            elif attr_type in ("ip-dst", "ip-src", "ip-dst|port"):
                ips.append(value.split("|")[0])
            elif attr_type == "url":
                host = urlparse(value).hostname or ""
                if host:
                    domains.append(host)

    summary.domains_added = await cache.add_domains(list(set(domains)), "misp")
    summary.ips_added = await cache.add_ips(list(set(ips)), "misp")
    logger.info(
        "MISP: %d domain(s) and %d IP(s) added",
        summary.domains_added, summary.ips_added,
    )
    return summary


# ── Combined refresh ─────────────────────────────────────────────────────────

async def refresh_all_feeds(cache: LocalBlocklistCache) -> list[FeedRefreshSummary]:
    """
    Refresh URLhaus, FeodoTracker, and MISP feeds concurrently.
    Returns a list of FeedRefreshSummary objects.
    """
    async with aiohttp.ClientSession(
        headers={"User-Agent": "Bubbble-ThreatIntel/1.0"}
    ) as session:
        results = await asyncio.gather(
            fetch_urlhaus(session, cache),
            fetch_feodotracker(session, cache),
            fetch_misp_feed(session, cache),
        )
    return list(results)


import asyncio  # noqa: E402 — placed after function definitions intentionally
