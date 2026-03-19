"""
Phase 5, Point 3 — Trusted Sender Whitelist

Allows influencers and creators to auto-trust links received from verified
brand partners, managers, or agencies. A URL from a trusted sender bypasses
the full cloud scan and is allowed through immediately (with a lightweight
local check against the phishing feed cache).

Data model
----------
TrustedSender  — a whitelisted contact (email, social handle, or phone number)
TrustedSenderStore — async CRUD backed by PostgreSQL (asyncpg)

Scanning integration
--------------------
Before sending a URL to the full URL Analysis Engine, the caller should check:

    checker = TrustedSenderLinkChecker(store, phish_checker)
    result = await checker.evaluate(user_id=42, sender_id="mgr@brand.com", url=url)
    if result.trusted_and_clean:
        # fast path — allow immediately
    else:
        # full scan path

Public API (to be wired into the FastAPI router)
-------------------------------------------------
    POST   /v1/trusted-senders          — add a sender
    GET    /v1/trusted-senders          — list senders for the authenticated user
    DELETE /v1/trusted-senders/{id}     — remove a sender
    GET    /v1/trusted-senders/{id}     — get a single sender
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import asyncpg

from backend.url_analysis.phishtank_openphish import PhishFeedChecker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SENDERS_PER_USER = 500   # Reasonable upper bound per account


# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------


class SenderType(str, Enum):
    EMAIL = "email"
    SOCIAL_HANDLE = "social_handle"  # @username on any platform
    PHONE = "phone"
    DOMAIN = "domain"                # Trust all links from a whole domain


@dataclass
class TrustedSender:
    id: str                         # UUID
    user_id: int                    # Bubbble account owner
    display_name: str               # Human label, e.g. "Nike Partnership Manager"
    sender_type: SenderType
    identifier: str                 # email / @handle / phone / domain
    platform: Optional[str]         # "instagram" | "whatsapp" | "email" | etc.
    notes: str = ""
    created_at: float = field(default_factory=time.time)
    active: bool = True


@dataclass
class TrustedSenderEvaluation:
    url: str
    sender_identifier: str
    sender_trusted: bool
    phish_hit: bool
    trusted_and_clean: bool         # True → fast-path allow
    reason: str


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9\s\-]{7,20}$")
_DOMAIN_RE = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_HANDLE_RE = re.compile(r"^@?[\w.]{1,50}$")


def _validate_identifier(sender_type: SenderType, identifier: str) -> str:
    """Normalise and validate an identifier. Returns cleaned value or raises ValueError."""
    identifier = identifier.strip()
    if sender_type == SenderType.EMAIL:
        if not _EMAIL_RE.match(identifier):
            raise ValueError(f"Invalid email: {identifier!r}")
        return identifier.lower()
    if sender_type == SenderType.PHONE:
        if not _PHONE_RE.match(identifier):
            raise ValueError(f"Invalid phone: {identifier!r}")
        return re.sub(r"[\s\-]", "", identifier)
    if sender_type == SenderType.DOMAIN:
        identifier = identifier.lstrip("https://").lstrip("http://").split("/")[0]
        if not _DOMAIN_RE.match(identifier):
            raise ValueError(f"Invalid domain: {identifier!r}")
        return identifier.lower()
    if sender_type == SenderType.SOCIAL_HANDLE:
        if not _HANDLE_RE.match(identifier):
            raise ValueError(f"Invalid handle: {identifier!r}")
        return identifier.lstrip("@").lower()
    raise ValueError(f"Unknown sender type: {sender_type}")


# ---------------------------------------------------------------------------
# PostgreSQL-backed store
# ---------------------------------------------------------------------------


# Schema (run once during migrations):
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS trusted_senders (
    id            TEXT PRIMARY KEY,
    user_id       BIGINT NOT NULL,
    display_name  TEXT NOT NULL,
    sender_type   TEXT NOT NULL,
    identifier    TEXT NOT NULL,
    platform      TEXT,
    notes         TEXT DEFAULT '',
    created_at    DOUBLE PRECISION NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (user_id, sender_type, identifier)
);
CREATE INDEX IF NOT EXISTS idx_ts_user_id ON trusted_senders (user_id);
CREATE INDEX IF NOT EXISTS idx_ts_identifier ON trusted_senders (identifier);
"""


class TrustedSenderStore:
    """Async CRUD operations for the trusted_senders table."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def add(
        self,
        user_id: int,
        display_name: str,
        sender_type: SenderType,
        identifier: str,
        platform: Optional[str] = None,
        notes: str = "",
    ) -> TrustedSender:
        """
        Add a trusted sender for *user_id*.
        Raises ValueError on invalid input or if the sender already exists.
        Raises PermissionError if the user has reached MAX_SENDERS_PER_USER.
        """
        cleaned = _validate_identifier(sender_type, identifier)

        count = await self._pool.fetchval(
            "SELECT COUNT(*) FROM trusted_senders WHERE user_id = $1 AND active = TRUE",
            user_id,
        )
        if count >= MAX_SENDERS_PER_USER:
            raise PermissionError(
                f"User {user_id} has reached the trusted sender limit ({MAX_SENDERS_PER_USER})."
            )

        sender = TrustedSender(
            id=str(uuid.uuid4()),
            user_id=user_id,
            display_name=display_name.strip(),
            sender_type=sender_type,
            identifier=cleaned,
            platform=platform,
            notes=notes,
        )

        try:
            await self._pool.execute(
                """
                INSERT INTO trusted_senders
                    (id, user_id, display_name, sender_type, identifier,
                     platform, notes, created_at, active)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                """,
                sender.id,
                sender.user_id,
                sender.display_name,
                sender.sender_type.value,
                sender.identifier,
                sender.platform,
                sender.notes,
                sender.created_at,
                sender.active,
            )
        except asyncpg.UniqueViolationError:
            raise ValueError(
                f"Sender {cleaned!r} is already in the whitelist for user {user_id}."
            )

        logger.info("Added trusted sender %s (%s) for user %d", cleaned, sender_type, user_id)
        return sender

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def list_for_user(self, user_id: int) -> list[TrustedSender]:
        rows = await self._pool.fetch(
            "SELECT * FROM trusted_senders WHERE user_id = $1 AND active = TRUE ORDER BY created_at DESC",
            user_id,
        )
        return [_row_to_sender(r) for r in rows]

    async def get(self, sender_id: str, user_id: int) -> Optional[TrustedSender]:
        row = await self._pool.fetchrow(
            "SELECT * FROM trusted_senders WHERE id = $1 AND user_id = $2",
            sender_id,
            user_id,
        )
        return _row_to_sender(row) if row else None

    async def is_trusted(
        self,
        user_id: int,
        sender_type: SenderType,
        identifier: str,
    ) -> bool:
        """
        Fast O(1) membership check — the primary hot path called during link scanning.
        """
        try:
            cleaned = _validate_identifier(sender_type, identifier)
        except ValueError:
            return False

        result = await self._pool.fetchval(
            """
            SELECT EXISTS(
                SELECT 1 FROM trusted_senders
                WHERE user_id=$1 AND sender_type=$2 AND identifier=$3 AND active=TRUE
            )
            """,
            user_id,
            sender_type.value,
            cleaned,
        )
        return bool(result)

    # ------------------------------------------------------------------
    # Delete (soft-delete)
    # ------------------------------------------------------------------

    async def remove(self, sender_id: str, user_id: int) -> bool:
        """
        Soft-delete a trusted sender (sets active=FALSE).
        Returns True if a row was updated, False if not found.
        """
        row = await self._pool.fetchrow(
            "UPDATE trusted_senders SET active=FALSE WHERE id=$1 AND user_id=$2 RETURNING id",
            sender_id,
            user_id,
        )
        updated = row is not None
        if updated:
            logger.info("Removed trusted sender %s for user %d", sender_id, user_id)
        return updated


def _row_to_sender(row: asyncpg.Record) -> TrustedSender:
    return TrustedSender(
        id=row["id"],
        user_id=row["user_id"],
        display_name=row["display_name"],
        sender_type=SenderType(row["sender_type"]),
        identifier=row["identifier"],
        platform=row["platform"],
        notes=row["notes"] or "",
        created_at=row["created_at"],
        active=row["active"],
    )


# ---------------------------------------------------------------------------
# Link evaluation helper (called by the URL Analysis Engine)
# ---------------------------------------------------------------------------


class TrustedSenderLinkChecker:
    """
    Combines trusted-sender whitelist lookup with a lightweight phishing-feed
    check. If the sender is trusted *and* the URL isn't in any phishing feed,
    the link is allowed through without a full deep scan.
    """

    def __init__(
        self,
        store: TrustedSenderStore,
        phish_checker: PhishFeedChecker,
    ) -> None:
        self._store = store
        self._phish = phish_checker

    async def evaluate(
        self,
        user_id: int,
        sender_identifier: str,
        sender_type: SenderType,
        url: str,
    ) -> TrustedSenderEvaluation:
        """
        Evaluate whether a URL from *sender_identifier* should be fast-pathed.

        Returns a :class:`TrustedSenderEvaluation` with `trusted_and_clean=True`
        if both conditions hold:
          1. The sender is in the user's whitelist.
          2. The URL does not appear in any phishing feed.
        """
        sender_trusted = await self._store.is_trusted(user_id, sender_type, sender_identifier)
        phish_hit = False

        if sender_trusted:
            hit = await self._phish.check_url(url)
            phish_hit = hit is not None

        trusted_and_clean = sender_trusted and not phish_hit

        if trusted_and_clean:
            reason = f"Sender '{sender_identifier}' is whitelisted and URL passed phishing feed check."
        elif sender_trusted and phish_hit:
            reason = (
                f"Sender '{sender_identifier}' is whitelisted BUT the URL was found in a phishing feed. "
                "Full scan required."
            )
        else:
            reason = f"Sender '{sender_identifier}' is not in the whitelist. Full scan required."

        return TrustedSenderEvaluation(
            url=url,
            sender_identifier=sender_identifier,
            sender_trusted=sender_trusted,
            phish_hit=phish_hit,
            trusted_and_clean=trusted_and_clean,
            reason=reason,
        )
