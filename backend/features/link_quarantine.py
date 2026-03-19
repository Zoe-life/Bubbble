"""
Phase 5, Point 2 — Link Quarantine Inbox

Routes suspicious links received via DMs and messages into a per-user
quarantine feed so they can be reviewed safely — without ever visiting them.

Workflow:
  1. A link arrives via DM, email, or comment webhook.
  2. Bubbble's ingestion endpoint routes it to the quarantine inbox instead
     of immediately scanning it (the user hasn't opened it yet).
  3. The user opens the Quarantine Inbox in the Bubbble app/extension.
  4. Each quarantined link shows a risk badge (from a lightweight pre-scan)
     and action buttons: "Scan & Open", "Mark Safe", "Block & Report".

Schema (DDL for reference):

    CREATE TABLE quarantine_inbox (
        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id         BIGINT NOT NULL,
        received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        source_platform VARCHAR(64) NOT NULL,
        sender_handle   VARCHAR(255),
        raw_url         TEXT NOT NULL,
        pre_scan_score  SMALLINT,          -- nullable; set after lightweight scan
        pre_scan_label  VARCHAR(32),       -- 'safe'|'suspicious'|'malicious'|null
        status          VARCHAR(32) NOT NULL DEFAULT 'pending',
                        -- 'pending'|'reviewed'|'blocked'|'allowed'
        reviewed_at     TIMESTAMPTZ
    );
    CREATE INDEX idx_quarantine_user_pending
      ON quarantine_inbox (user_id, received_at DESC)
      WHERE status = 'pending';
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

MAX_QUARANTINE_PER_USER = 500  # keep inbox manageable


# ── Models ────────────────────────────────────────────────────────────────────

class QuarantineStatus(str, Enum):
    PENDING = "pending"
    REVIEWED = "reviewed"
    BLOCKED = "blocked"
    ALLOWED = "allowed"


@dataclass
class QuarantineItem:
    item_id: str
    user_id: int
    received_at: str
    source_platform: str         # "whatsapp" | "instagram_dm" | "email" | "twitter_dm" etc.
    sender_handle: Optional[str]
    raw_url: str
    pre_scan_score: Optional[int] = None   # 0–100 from lightweight scan
    pre_scan_label: Optional[str] = None   # "safe" | "suspicious" | "malicious"
    status: str = QuarantineStatus.PENDING.value
    reviewed_at: Optional[str] = None

    @classmethod
    def create(
        cls,
        user_id: int,
        source_platform: str,
        raw_url: str,
        sender_handle: Optional[str] = None,
    ) -> "QuarantineItem":
        return cls(
            item_id=str(uuid.uuid4()),
            user_id=user_id,
            received_at=datetime.now(tz=timezone.utc).isoformat(),
            source_platform=source_platform,
            sender_handle=sender_handle,
            raw_url=raw_url,
        )

    @property
    def risk_badge(self) -> str:
        if self.pre_scan_label == "malicious":
            return "🔴 Malicious"
        if self.pre_scan_label == "suspicious":
            return "🟡 Suspicious"
        if self.pre_scan_label == "safe":
            return "🟢 Safe"
        return "⚪ Not scanned"


# ── Quarantine store ──────────────────────────────────────────────────────────

class QuarantineInbox:
    """
    Per-user link quarantine inbox, backed by asyncpg (PostgreSQL).

    Usage::

        inbox = QuarantineInbox(pool)

        # Add a link to quarantine
        item = await inbox.enqueue(
            user_id=42,
            source_platform="whatsapp",
            raw_url="https://bit.ly/suspicious",
            sender_handle="+254700000000",
        )

        # List pending items
        items = await inbox.list_pending(user_id=42)

        # Mark as blocked after user review
        await inbox.update_status(item.item_id, QuarantineStatus.BLOCKED)
    """

    def __init__(self, pool) -> None:
        self._pool = pool

    async def enqueue(
        self,
        user_id: int,
        source_platform: str,
        raw_url: str,
        sender_handle: Optional[str] = None,
        pre_scan_score: Optional[int] = None,
        pre_scan_label: Optional[str] = None,
    ) -> QuarantineItem:
        """
        Add a URL to the user's quarantine inbox.
        Drops the oldest pending entry if the inbox is at capacity.
        """
        await self._enforce_capacity(user_id)

        item = QuarantineItem.create(
            user_id=user_id,
            source_platform=source_platform,
            raw_url=raw_url,
            sender_handle=sender_handle,
        )
        item.pre_scan_score = pre_scan_score
        item.pre_scan_label = pre_scan_label

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO quarantine_inbox
                    (id, user_id, received_at, source_platform, sender_handle,
                     raw_url, pre_scan_score, pre_scan_label, status)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """,
                uuid.UUID(item.item_id),
                user_id,
                datetime.fromisoformat(item.received_at),
                source_platform,
                sender_handle,
                raw_url,
                pre_scan_score,
                pre_scan_label,
                QuarantineStatus.PENDING.value,
            )
        logger.info(
            "Quarantined URL for user %d: %s (platform=%s)", user_id, raw_url, source_platform
        )
        return item

    async def list_pending(
        self,
        user_id: int,
        limit: int = 50,
    ) -> list[QuarantineItem]:
        """Return the most recent *limit* pending quarantine items."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, user_id, received_at, source_platform, sender_handle,
                       raw_url, pre_scan_score, pre_scan_label, status, reviewed_at
                FROM quarantine_inbox
                WHERE user_id = $1 AND status = 'pending'
                ORDER BY received_at DESC
                LIMIT $2
                """,
                user_id, limit,
            )
        return [_row_to_item(r) for r in rows]

    async def list_all(
        self,
        user_id: int,
        limit: int = 100,
    ) -> list[QuarantineItem]:
        """Return all quarantine items (all statuses) for review history."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, user_id, received_at, source_platform, sender_handle,
                       raw_url, pre_scan_score, pre_scan_label, status, reviewed_at
                FROM quarantine_inbox
                WHERE user_id = $1
                ORDER BY received_at DESC
                LIMIT $2
                """,
                user_id, limit,
            )
        return [_row_to_item(r) for r in rows]

    async def update_status(
        self,
        item_id: str,
        new_status: QuarantineStatus,
    ) -> bool:
        """
        Update the status of a quarantine item (e.g., after the user reviews it).
        Returns True if a row was updated.
        """
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE quarantine_inbox
                SET status = $1, reviewed_at = NOW()
                WHERE id = $2
                RETURNING id
                """,
                new_status.value,
                uuid.UUID(item_id),
            )
        updated = result.split()[-1] != "0"
        if updated:
            logger.info("Quarantine item %s → %s", item_id, new_status.value)
        return updated

    async def update_pre_scan(
        self,
        item_id: str,
        score: int,
        label: str,
    ) -> None:
        """Update the lightweight pre-scan result for a quarantined item."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE quarantine_inbox
                SET pre_scan_score = $1, pre_scan_label = $2
                WHERE id = $3
                """,
                score, label, uuid.UUID(item_id),
            )

    async def pending_count(self, user_id: int) -> int:
        async with self._pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT COUNT(*) FROM quarantine_inbox WHERE user_id=$1 AND status='pending'",
                user_id,
            ) or 0

    # ── Capacity management ───────────────────────────────────────────────────

    async def _enforce_capacity(self, user_id: int) -> None:
        """If the inbox is at capacity, drop the oldest pending item."""
        async with self._pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM quarantine_inbox WHERE user_id=$1 AND status='pending'",
                user_id,
            ) or 0

            if count >= MAX_QUARANTINE_PER_USER:
                await conn.execute(
                    """
                    DELETE FROM quarantine_inbox
                    WHERE id = (
                        SELECT id FROM quarantine_inbox
                        WHERE user_id = $1 AND status = 'pending'
                        ORDER BY received_at ASC
                        LIMIT 1
                    )
                    """,
                    user_id,
                )
                logger.info(
                    "Quarantine inbox at capacity for user %d — oldest entry evicted", user_id
                )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _row_to_item(row: dict) -> QuarantineItem:
    return QuarantineItem(
        item_id=str(row["id"]),
        user_id=row["user_id"],
        received_at=row["received_at"].isoformat(),
        source_platform=row["source_platform"],
        sender_handle=row["sender_handle"],
        raw_url=row["raw_url"],
        pre_scan_score=row["pre_scan_score"],
        pre_scan_label=row["pre_scan_label"],
        status=row["status"],
        reviewed_at=row["reviewed_at"].isoformat() if row["reviewed_at"] else None,
    )
