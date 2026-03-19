"""
Phase 1 — Threat Intelligence Database: Local Blocklist Cache

Maintains an in-memory and Redis-backed blocklist of known-bad domains and
IP addresses, populated from multiple threat intelligence sources.

The blocklist serves as the fastest-path check — before any external API call
is made. If a domain or IP is already in the local cache, the URL is
immediately flagged without incurring API latency or rate-limit costs.

Data sources feeding this blocklist:
  - MISP feeds
  - abuse.ch (URLhaus, FeodoTracker)
  - Custom manual additions
  - Expired / evicted entries from PhishTank / OpenPhish (see phishtank_openphish.py)
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import aioredis

logger = logging.getLogger(__name__)

REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379")
BLOCKLIST_DOMAINS_KEY = "bubbble:blocklist:domains"   # Redis Set
BLOCKLIST_IPS_KEY = "bubbble:blocklist:ips"            # Redis Set
BLOCKLIST_META_KEY = "bubbble:blocklist:meta"
CACHE_TTL_SECONDS = 86_400  # 24 h — refreshed by the scheduler before expiry


@dataclass
class BlocklistHit:
    value: str           # blocked domain or IP
    hit_type: str        # "domain" | "ip"
    source: str          # e.g. "misp", "abusech_urlhaus", "manual"


class LocalBlocklistCache:
    """
    Fast O(1) local blocklist lookup backed by Redis Sets.

    Usage::

        cache = LocalBlocklistCache()
        await cache.connect()
        hit = await cache.check_url("https://evil.example.com")
        if hit:
            print(f"Blocked: {hit.value} ({hit.source})")
        await cache.close()
    """

    def __init__(self) -> None:
        self._redis: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        self._redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        logger.info("LocalBlocklistCache connected (Redis: %s)", REDIS_URL)

    async def close(self) -> None:
        if self._redis:
            await self._redis.close()

    # ── Lookup ───────────────────────────────────────────────────────

    async def check_url(self, url: str) -> Optional[BlocklistHit]:
        """
        Check a URL's domain and IP against the local blocklist.
        Returns a BlocklistHit if found, None otherwise.
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        checks = [self._check_domain(host)]

        # If host looks like an IP address, check the IP list too
        try:
            ipaddress.ip_address(host)
            checks.append(self._check_ip(host))
        except ValueError:
            pass

        results = await asyncio.gather(*checks)
        for r in results:
            if r:
                return r
        return None

    async def _check_domain(self, domain: str) -> Optional[BlocklistHit]:
        if not domain:
            return None
        h = _sha256(domain)
        # Check exact domain and apex domain (strips one subdomain level)
        apex = _apex_domain(domain)
        apex_h = _sha256(apex)
        for key, source in [(h, domain), (apex_h, apex)]:
            member_meta = await self._redis.hget(BLOCKLIST_DOMAINS_KEY + ":meta", key)
            if await self._redis.sismember(BLOCKLIST_DOMAINS_KEY, key):
                src = member_meta or "blocklist"
                return BlocklistHit(value=source, hit_type="domain", source=src)
        return None

    async def _check_ip(self, ip: str) -> Optional[BlocklistHit]:
        h = _sha256(ip)
        src = await self._redis.hget(BLOCKLIST_IPS_KEY + ":meta", h)
        if await self._redis.sismember(BLOCKLIST_IPS_KEY, h):
            return BlocklistHit(value=ip, hit_type="ip", source=src or "blocklist")
        return None

    # ── Write ────────────────────────────────────────────────────────

    async def add_domains(self, domains: list[str], source: str) -> int:
        """Add a batch of domains to the blocklist. Returns count added."""
        if not domains:
            return 0
        pipe = self._redis.pipeline()
        for domain in domains:
            h = _sha256(domain.lower())
            pipe.sadd(BLOCKLIST_DOMAINS_KEY, h)
            pipe.hset(BLOCKLIST_DOMAINS_KEY + ":meta", h, source)
        pipe.expire(BLOCKLIST_DOMAINS_KEY, CACHE_TTL_SECONDS)
        pipe.expire(BLOCKLIST_DOMAINS_KEY + ":meta", CACHE_TTL_SECONDS)
        await pipe.execute()
        logger.info("Blocklist: added %d domain(s) from %s", len(domains), source)
        return len(domains)

    async def add_ips(self, ips: list[str], source: str) -> int:
        """Add a batch of IP addresses to the blocklist. Returns count added."""
        if not ips:
            return 0
        pipe = self._redis.pipeline()
        for ip in ips:
            h = _sha256(ip)
            pipe.sadd(BLOCKLIST_IPS_KEY, h)
            pipe.hset(BLOCKLIST_IPS_KEY + ":meta", h, source)
        pipe.expire(BLOCKLIST_IPS_KEY, CACHE_TTL_SECONDS)
        pipe.expire(BLOCKLIST_IPS_KEY + ":meta", CACHE_TTL_SECONDS)
        await pipe.execute()
        logger.info("Blocklist: added %d IP(s) from %s", len(ips), source)
        return len(ips)

    async def stats(self) -> dict:
        domain_count = await self._redis.scard(BLOCKLIST_DOMAINS_KEY)
        ip_count = await self._redis.scard(BLOCKLIST_IPS_KEY)
        return {"domains": domain_count, "ips": ip_count}


# ── Helpers ──────────────────────────────────────────────────────────

def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _apex_domain(host: str) -> str:
    """Return the apex (eTLD+1) of a hostname by stripping one subdomain level."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host
