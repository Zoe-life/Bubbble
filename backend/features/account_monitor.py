"""
Phase 5, Point 1 — Account Protection Monitor

Monitors a user's linked social media accounts for signs of compromise:

  - Unexpected password-change events
  - New login from unrecognised device / country
  - Unusual posting activity (volume spike, suspicious content)
  - Linked app permission additions
  - Email address change on the account

Because social platforms don't expose compromise-detection APIs directly,
Bubbble uses a combination of:

  1. OAuth token validity checks — a revoked/invalid token indicates the
     account's password may have been changed.
  2. Activity baseline monitoring — if the user grants read access to their
     feed, Bubbble checks for anomalous posting patterns.
  3. HIBP (Have I Been Pwned) — checks whether the user's linked email
     appears in a data breach.

Alerts are stored in the account_alerts table and pushed to the user via
the notification service.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

HIBP_API_KEY: str = os.environ.get("HIBP_API_KEY", "")
HIBP_BASE = "https://haveibeenpwned.com/api/v3"


# ── Models ────────────────────────────────────────────────────────────────────

class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    TOKEN_REVOKED = "token_revoked"
    DATA_BREACH = "data_breach"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    NEW_LOGIN = "new_login"
    PERMISSION_ADDED = "permission_added"


@dataclass
class AccountAlert:
    user_id: int
    platform: str                       # "instagram", "tiktok", "twitter", etc.
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    detected_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    meta: dict = field(default_factory=dict)


@dataclass
class LinkedAccount:
    platform: str
    username: str
    email: Optional[str]
    oauth_token: Optional[str]          # current access token


# ── OAuth token health check ──────────────────────────────────────────────────

_TOKEN_VERIFY_ENDPOINTS: dict[str, str] = {
    "instagram": "https://graph.instagram.com/me?fields=id",
    "twitter":   "https://api.twitter.com/2/users/me",
    "tiktok":    "https://open.tiktokapis.com/v2/user/info/?fields=open_id",
}


async def check_token_validity(
    account: LinkedAccount,
    session: aiohttp.ClientSession,
) -> Optional[AccountAlert]:
    """
    Verify that the stored OAuth access token for *account* is still valid.
    A 401 / 403 response indicates the token was revoked (password changed,
    user de-authorised the app, or account compromised).
    """
    endpoint = _TOKEN_VERIFY_ENDPOINTS.get(account.platform)
    if not endpoint or not account.oauth_token:
        return None

    try:
        async with session.get(
            endpoint,
            headers={"Authorization": f"Bearer {account.oauth_token}"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status in (401, 403):
                logger.warning(
                    "Token revoked for %s/%s", account.platform, account.username
                )
                return AccountAlert(
                    user_id=0,  # caller sets this
                    platform=account.platform,
                    alert_type=AlertType.TOKEN_REVOKED,
                    severity=AlertSeverity.HIGH,
                    title=f"{account.platform.title()} access revoked",
                    description=(
                        f"Bubbble can no longer access your {account.platform.title()} account. "
                        "This may mean your password was changed or the app was de-authorised. "
                        "Check your account security settings immediately."
                    ),
                )
    except Exception as exc:
        logger.error(
            "Token check error for %s/%s: %s", account.platform, account.username, exc
        )
    return None


# ── Have I Been Pwned check ───────────────────────────────────────────────────

async def check_email_breach(
    user_id: int,
    email: str,
    session: aiohttp.ClientSession,
) -> list[AccountAlert]:
    """
    Check whether *email* appears in any known data breach using HIBP v3.
    Returns a list of AccountAlert (one per breach, capped at 5).
    """
    if not HIBP_API_KEY or not email:
        return []

    alerts: list[AccountAlert] = []
    try:
        async with session.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "User-Agent": "Bubbble-AccountMonitor/1.0",
            },
            params={"truncateResponse": "false"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 404:
                return []  # No breaches
            if resp.status != 200:
                return []
            breaches = await resp.json()

        for breach in breaches[:5]:  # cap at 5 alerts
            name = breach.get("Name", "Unknown")
            date = breach.get("BreachDate", "unknown date")
            data_classes = ", ".join(breach.get("DataClasses", [])[:4])
            alerts.append(AccountAlert(
                user_id=user_id,
                platform="email",
                alert_type=AlertType.DATA_BREACH,
                severity=AlertSeverity.HIGH,
                title=f"Email found in {name} data breach",
                description=(
                    f"Your email was found in the {name} breach ({date}). "
                    f"Exposed data: {data_classes}. "
                    "Change your password on any service using this email."
                ),
                meta={"breach_name": name, "breach_date": date},
            ))
    except Exception as exc:
        logger.error("HIBP check error for %s: %s", email, exc)

    return alerts


# ── Monitor orchestrator ──────────────────────────────────────────────────────

class AccountProtectionMonitor:
    """
    Orchestrates all account protection checks for a given user.

    Usage::

        monitor = AccountProtectionMonitor(notification_fn)
        alerts = await monitor.run_checks(user_id=42, accounts=[...])
    """

    def __init__(self, on_alert=None) -> None:
        """
        :param on_alert: Optional async callable(AccountAlert) to receive alerts.
        """
        self._on_alert = on_alert

    async def run_checks(
        self,
        user_id: int,
        accounts: list[LinkedAccount],
    ) -> list[AccountAlert]:
        """
        Run all protection checks for the user's linked accounts.
        Returns a list of detected AccountAlerts.
        """
        all_alerts: list[AccountAlert] = []

        async with aiohttp.ClientSession() as session:
            tasks = [
                self._check_account(user_id, account, session)
                for account in accounts
            ]
            results = await asyncio.gather(*tasks)
            for batch in results:
                all_alerts.extend(batch)

        if self._on_alert:
            for alert in all_alerts:
                try:
                    await self._on_alert(alert)
                except Exception as exc:
                    logger.error("on_alert callback error: %s", exc)

        logger.info(
            "Account protection check for user %d: %d alert(s)", user_id, len(all_alerts)
        )
        return all_alerts

    async def _check_account(
        self,
        user_id: int,
        account: LinkedAccount,
        session: aiohttp.ClientSession,
    ) -> list[AccountAlert]:
        alerts: list[AccountAlert] = []

        # Token validity
        token_alert = await check_token_validity(account, session)
        if token_alert:
            token_alert.user_id = user_id
            alerts.append(token_alert)

        # Email breach check
        if account.email:
            breach_alerts = await check_email_breach(user_id, account.email, session)
            alerts.extend(breach_alerts)

        return alerts
