"""
Phase 1 — Threat Intelligence Auto-Refresh Scheduler

Runs the threat intelligence feed refresh loop every 15 minutes, keeping
the local blocklist and phishing feeds current with minimal operator
intervention.

Integrates:
  - PhishTank + OpenPhish (phishtank_openphish.py)
  - URLhaus + FeodoTracker + MISP (misp_abusech.py)

Intended to be started once on application startup::

    import asyncio
    from backend.threat_intel.scheduler import ThreatIntelScheduler

    scheduler = ThreatIntelScheduler()
    asyncio.create_task(scheduler.run())
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from backend.threat_intel.local_blocklist import LocalBlocklistCache
from backend.threat_intel.misp_abusech import refresh_all_feeds
from backend.url_analysis.phishtank_openphish import PhishFeedChecker

logger = logging.getLogger(__name__)

REFRESH_INTERVAL_SECONDS: int = int(
    os.environ.get("THREAT_INTEL_REFRESH_INTERVAL", 900)  # 15 minutes
)


@dataclass
class SchedulerStatus:
    last_run_at: Optional[float] = None
    last_run_duration_s: float = 0.0
    run_count: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    feed_summaries: list = field(default_factory=list)


class ThreatIntelScheduler:
    """
    Coordinates the 15-minute refresh cycle for all threat intelligence feeds.

    Usage::

        scheduler = ThreatIntelScheduler()
        await scheduler.start()          # begins background loop
        # ... later ...
        await scheduler.stop()
    """

    def __init__(self) -> None:
        self._blocklist = LocalBlocklistCache()
        self._phish_checker = PhishFeedChecker()
        self._status = SchedulerStatus()
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self) -> None:
        await self._blocklist.connect()
        await self._phish_checker.connect()
        logger.info(
            "ThreatIntelScheduler starting (interval: %ds)", REFRESH_INTERVAL_SECONDS
        )
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._blocklist.close()
        await self._phish_checker.close()
        logger.info("ThreatIntelScheduler stopped")

    # ── Main loop ────────────────────────────────────────────────────

    async def run(self) -> None:
        """
        Run the refresh loop indefinitely until stop() is called or the task
        is cancelled. On startup, performs an immediate refresh.
        """
        while not self._stop_event.is_set():
            await self._run_refresh_cycle()
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=REFRESH_INTERVAL_SECONDS,
                )
            except asyncio.TimeoutError:
                pass  # normal — just time for the next cycle

    async def _run_refresh_cycle(self) -> None:
        start_time = time.monotonic()
        self._status.run_count += 1
        logger.info(
            "ThreatIntel refresh cycle #%d starting", self._status.run_count
        )
        try:
            # Run both feed groups concurrently
            phish_stats, feed_summaries = await asyncio.gather(
                self._phish_checker.refresh_feeds(),
                refresh_all_feeds(self._blocklist),
            )

            blocklist_stats = await self._blocklist.stats()
            self._status.feed_summaries = feed_summaries
            self._status.last_error = None

            logger.info(
                "ThreatIntel refresh complete: blocklist=%s, phish stats=%s",
                blocklist_stats,
                [(s.source, s.entry_count) for s in phish_stats],
            )
        except Exception as exc:
            self._status.error_count += 1
            self._status.last_error = str(exc)
            logger.error("ThreatIntel refresh cycle failed: %s", exc)
        finally:
            self._status.last_run_at = time.time()
            self._status.last_run_duration_s = time.monotonic() - start_time

    # ── Status ───────────────────────────────────────────────────────

    def get_status(self) -> SchedulerStatus:
        return self._status

    @property
    def blocklist(self) -> LocalBlocklistCache:
        return self._blocklist

    @property
    def phish_checker(self) -> PhishFeedChecker:
        return self._phish_checker
