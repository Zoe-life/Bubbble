"""
Phase 1 — WHOIS / Domain-Age Check

Determines how long a domain has been registered. Newly registered domains
(< 30 days) are a strong indicator of phishing infrastructure.

Uses the python-whois library. Falls back gracefully when WHOIS data is
unavailable (rate-limited, private registration, etc.).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import whois  # python-whois

logger = logging.getLogger(__name__)

# Risk thresholds (days since registration)
VERY_NEW_THRESHOLD_DAYS = 7
NEW_THRESHOLD_DAYS = 30
SUSPICIOUS_THRESHOLD_DAYS = 90


@dataclass
class WhoisResult:
    domain: str
    registrar: Optional[str]
    creation_date: Optional[datetime]
    expiry_date: Optional[datetime]
    age_days: Optional[int]
    registrant_country: Optional[str]

    @property
    def risk_label(self) -> str:
        if self.age_days is None:
            return "unknown"
        if self.age_days < VERY_NEW_THRESHOLD_DAYS:
            return "very_new"
        if self.age_days < NEW_THRESHOLD_DAYS:
            return "new"
        if self.age_days < SUSPICIOUS_THRESHOLD_DAYS:
            return "suspicious"
        return "established"

    @property
    def risk_score_contribution(self) -> int:
        """Returns 0–30 points contribution to the overall risk score."""
        label_scores = {
            "very_new": 30,
            "new": 20,
            "suspicious": 10,
            "established": 0,
            "unknown": 5,
        }
        return label_scores.get(self.risk_label, 5)


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Strip www. prefix for cleaner WHOIS lookup
        return host.removeprefix("www.")
    except Exception:
        return url


def _parse_date(raw) -> Optional[datetime]:
    """Normalise WHOIS date — can be a datetime, list of datetimes, or None."""
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0]
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw
    return None


async def check_domain_age(url: str) -> WhoisResult:
    """
    Perform a WHOIS lookup for the domain in *url* and return a WhoisResult.
    This is a blocking I/O call wrapped in a thread-safe way.
    Run inside an executor in production: ``asyncio.to_thread(check_domain_age, url)``
    """
    domain = _extract_domain(url)
    try:
        w = whois.whois(domain)
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return WhoisResult(
            domain=domain,
            registrar=None,
            creation_date=None,
            expiry_date=None,
            age_days=None,
            registrant_country=None,
        )

    creation_date = _parse_date(getattr(w, "creation_date", None))
    expiry_date = _parse_date(getattr(w, "expiration_date", None))
    age_days: Optional[int] = None
    if creation_date:
        age_days = (datetime.now(tz=timezone.utc) - creation_date).days

    registrar = getattr(w, "registrar", None)
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None

    country = getattr(w, "country", None)
    if isinstance(country, list):
        country = country[0] if country else None

    result = WhoisResult(
        domain=domain,
        registrar=registrar,
        creation_date=creation_date,
        expiry_date=expiry_date,
        age_days=age_days,
        registrant_country=country,
    )
    logger.info(
        "WHOIS %s: age=%s days (%s)", domain, age_days, result.risk_label
    )
    return result
