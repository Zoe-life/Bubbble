"""
Phase 1, Point 3 — PhishTank / OpenPhish Feed Integration
Fetches, caches, and queries phishing URL databases from PhishTank and OpenPhish.

Feed refresh runs every 15 minutes via background scheduler (see scheduler setup below).
All lookups are O(1) via in-memory sets backed by a Redis cache.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp
import aioredis

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------

PHISHTANK_API_KEY: str = os.environ.get("PHISHTANK_API_KEY", "")
# "developer" is the recognised path for unauthenticated PhishTank feed access.
# When a real API key is set it replaces this placeholder in the URL.
PHISHTANK_ANON_PATH: str = "developer"
PHISHTANK_FEED_URL: str = (
    "http://data.phishtank.com/data/{api_key}/online-valid.json"
)
OPENPHISH_FEED_URL: str = "https://openphish.com/feed.txt"

CACHE_TTL_SECONDS: int = int(os.environ.get("PHISH_CACHE_TTL", 900))  # 15 min
REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379")

PHISHTANK_REDIS_KEY = "bubbble:phishtank:urls"
OPENPHISH_REDIS_KEY = "bubbble:openphish:urls"
PHISHTANK_META_KEY = "bubbble:phishtank:meta"
OPENPHISH_META_KEY = "bubbble:openphish:meta"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PhishHit:
    """Result returned when a URL matches a phishing feed."""

    url: str
    source: str          # "phishtank" | "openphish"
    phish_id: Optional[str] = None          # PhishTank phish_id (if available)
    verified: Optional[bool] = None         # PhishTank verified flag
    target: Optional[str] = None            # Targeted brand (PhishTank)
    submission_time: Optional[str] = None   # ISO-8601 timestamp


@dataclass
class FeedStats:
    source: str
    last_refreshed_at: Optional[float] = None
    entry_count: int = 0
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_url(url: str) -> str:
    """
    Produce a canonical form of a URL for set-membership lookups.
    Strips trailing slashes and lowercases the scheme + host.
    """
    try:
        parsed = urlparse(url.strip())
        normalised = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
        ).geturl()
        return normalised.rstrip("/")
    except Exception:
        return url.strip().rstrip("/")


def _url_hash(url: str) -> str:
    """SHA-256 hex digest of a normalised URL (used as Redis set member)."""
    return hashlib.sha256(_normalise_url(url).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Feed fetchers
# ---------------------------------------------------------------------------

async def _fetch_phishtank(session: aiohttp.ClientSession) -> list[dict]:
    """
    Download the PhishTank online-valid JSON feed.
    Returns a list of phish entry dicts with keys:
      phish_id, url, phish_detail_url, submission_time, verified, target
    """
    api_key_path = PHISHTANK_API_KEY if PHISHTANK_API_KEY else PHISHTANK_ANON_PATH
    url = PHISHTANK_FEED_URL.format(api_key=api_key_path)
    logger.info("Fetching PhishTank feed from %s", url)
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
        resp.raise_for_status()
        data = await resp.json(content_type=None)
    logger.info("PhishTank feed: %d entries fetched", len(data))
    return data


async def _fetch_openphish(session: aiohttp.ClientSession) -> list[str]:
    """
    Download the OpenPhish community feed (plain text, one URL per line).
    Returns a list of raw URL strings.
    """
    logger.info("Fetching OpenPhish feed from %s", OPENPHISH_FEED_URL)
    async with session.get(
        OPENPHISH_FEED_URL, timeout=aiohttp.ClientTimeout(total=30)
    ) as resp:
        resp.raise_for_status()
        text = await resp.text()
    urls = [line.strip() for line in text.splitlines() if line.strip()]
    logger.info("OpenPhish feed: %d entries fetched", len(urls))
    return urls


# ---------------------------------------------------------------------------
# Redis persistence
# ---------------------------------------------------------------------------

async def _store_phishtank(redis: aioredis.Redis, entries: list[dict]) -> int:
    """
    Persist PhishTank entries in Redis.
    Uses a Redis Hash: field = url_hash, value = JSON-serialised entry.
    """
    pipe = redis.pipeline()
    pipe.delete(PHISHTANK_REDIS_KEY)
    for entry in entries:
        raw_url = entry.get("url", "")
        if not raw_url:
            continue
        key = _url_hash(raw_url)
        pipe.hset(PHISHTANK_REDIS_KEY, key, json.dumps(entry))
    pipe.expire(PHISHTANK_REDIS_KEY, CACHE_TTL_SECONDS)
    pipe.hset(
        PHISHTANK_META_KEY,
        "last_refreshed_at",
        str(time.time()),
    )
    pipe.hset(PHISHTANK_META_KEY, "entry_count", str(len(entries)))
    pipe.expire(PHISHTANK_META_KEY, CACHE_TTL_SECONDS)
    await pipe.execute()
    return len(entries)


async def _store_openphish(redis: aioredis.Redis, urls: list[str]) -> int:
    """
    Persist OpenPhish URLs in Redis.
    Uses a Redis Set of url_hashes for O(1) membership testing.
    """
    pipe = redis.pipeline()
    pipe.delete(OPENPHISH_REDIS_KEY)
    for url in urls:
        pipe.sadd(OPENPHISH_REDIS_KEY, _url_hash(url))
    pipe.expire(OPENPHISH_REDIS_KEY, CACHE_TTL_SECONDS)
    pipe.hset(
        OPENPHISH_META_KEY,
        "last_refreshed_at",
        str(time.time()),
    )
    pipe.hset(OPENPHISH_META_KEY, "entry_count", str(len(urls)))
    pipe.expire(OPENPHISH_META_KEY, CACHE_TTL_SECONDS)
    await pipe.execute()
    return len(urls)


# ---------------------------------------------------------------------------
# Main public interface
# ---------------------------------------------------------------------------

class PhishFeedChecker:
    """
    Checks a URL against the PhishTank and OpenPhish phishing-URL feeds.

    Usage::

        checker = PhishFeedChecker()
        await checker.connect()
        await checker.refresh_feeds()          # call on startup & every 15 min
        hit = await checker.check_url("https://evil-phish.example.com/login")
        if hit:
            print(f"PHISHING detected via {hit.source}: {hit.url}")
        await checker.close()
    """

    def __init__(self) -> None:
        self._redis: Optional[aioredis.Redis] = None
        self._session: Optional[aiohttp.ClientSession] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        self._redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        self._session = aiohttp.ClientSession(
            headers={"User-Agent": "Bubbble-PhishChecker/1.0"}
        )
        logger.info("PhishFeedChecker connected (Redis: %s)", REDIS_URL)

    async def close(self) -> None:
        if self._session:
            await self._session.close()
        if self._redis:
            await self._redis.close()

    # ------------------------------------------------------------------
    # Feed refresh
    # ------------------------------------------------------------------

    async def refresh_feeds(self) -> tuple[FeedStats, FeedStats]:
        """
        Refresh both feeds concurrently.
        Returns (phishtank_stats, openphish_stats).
        Called on startup and then every CACHE_TTL_SECONDS by the scheduler.
        """
        pt_stats, op_stats = await asyncio.gather(
            self._refresh_phishtank(),
            self._refresh_openphish(),
        )
        return pt_stats, op_stats

    async def _refresh_phishtank(self) -> FeedStats:
        stats = FeedStats(source="phishtank")
        try:
            entries = await _fetch_phishtank(self._session)
            count = await _store_phishtank(self._redis, entries)
            stats.entry_count = count
            stats.last_refreshed_at = time.time()
            logger.info("PhishTank feed refreshed: %d entries stored", count)
        except Exception as exc:
            stats.error = str(exc)
            logger.error("PhishTank feed refresh failed: %s", exc)
        return stats

    async def _refresh_openphish(self) -> FeedStats:
        stats = FeedStats(source="openphish")
        try:
            urls = await _fetch_openphish(self._session)
            count = await _store_openphish(self._redis, urls)
            stats.entry_count = count
            stats.last_refreshed_at = time.time()
            logger.info("OpenPhish feed refreshed: %d entries stored", count)
        except Exception as exc:
            stats.error = str(exc)
            logger.error("OpenPhish feed refresh failed: %s", exc)
        return stats

    # ------------------------------------------------------------------
    # URL checking
    # ------------------------------------------------------------------

    async def check_url(self, url: str) -> Optional[PhishHit]:
        """
        Check a URL against both feeds.
        Returns a PhishHit if the URL matches any feed, otherwise None.
        PhishTank is checked first (richer metadata); OpenPhish as fallback.
        """
        h = _url_hash(url)

        # 1. PhishTank — hash lookup in Redis Hash
        raw = await self._redis.hget(PHISHTANK_REDIS_KEY, h)
        if raw:
            entry = json.loads(raw)
            return PhishHit(
                url=url,
                source="phishtank",
                phish_id=entry.get("phish_id"),
                verified=entry.get("verified") == "yes",
                target=entry.get("target"),
                submission_time=entry.get("submission_time"),
            )

        # 2. OpenPhish — hash membership in Redis Set
        if await self._redis.sismember(OPENPHISH_REDIS_KEY, h):
            return PhishHit(url=url, source="openphish")

        return None

    async def check_urls_batch(self, urls: list[str]) -> dict[str, Optional[PhishHit]]:
        """Check multiple URLs concurrently. Returns {url: PhishHit | None}."""
        results = await asyncio.gather(*(self.check_url(u) for u in urls))
        return dict(zip(urls, results))

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(self) -> list[FeedStats]:
        """Return current feed statistics from Redis metadata."""
        stats = []
        for source, meta_key in [
            ("phishtank", PHISHTANK_META_KEY),
            ("openphish", OPENPHISH_META_KEY),
        ]:
            meta = await self._redis.hgetall(meta_key)
            s = FeedStats(
                source=source,
                last_refreshed_at=float(meta["last_refreshed_at"])
                if meta.get("last_refreshed_at")
                else None,
                entry_count=int(meta.get("entry_count", 0)),
            )
            stats.append(s)
        return stats


# ---------------------------------------------------------------------------
# Background scheduler (standalone entry point)
# ---------------------------------------------------------------------------

async def run_feed_scheduler() -> None:
    """
    Run the feed refresh loop indefinitely.
    Intended to be started once on application startup, e.g.::

        asyncio.create_task(run_feed_scheduler())
    """
    checker = PhishFeedChecker()
    await checker.connect()
    try:
        while True:
            logger.info("Scheduler: refreshing PhishTank & OpenPhish feeds")
            await checker.refresh_feeds()
            logger.info(
                "Scheduler: next refresh in %d seconds", CACHE_TTL_SECONDS
            )
            await asyncio.sleep(CACHE_TTL_SECONDS)
    finally:
        await checker.close()
