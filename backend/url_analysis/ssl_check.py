"""
Phase 1 — SSL/TLS Certificate Validation

Connects to a host and inspects its TLS certificate.
A missing or invalid certificate is a strong phishing indicator.

Checks:
  - Certificate presence
  - Expiry date
  - Hostname match (via ssl.match_hostname semantics)
  - Self-signed vs. CA-signed detection
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 8  # seconds


@dataclass
class SSLResult:
    host: str
    port: int
    cert_present: bool
    cert_valid: bool            # True if no ssl.SSLError occurred
    subject_cn: Optional[str]
    issuer_o: Optional[str]     # Issuer organisation
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    days_until_expiry: Optional[int]
    error: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        if self.not_after is None:
            return False
        return self.not_after < datetime.now(tz=timezone.utc)

    @property
    def risk_score_contribution(self) -> int:
        """Returns 0–25 points contribution to the overall risk score."""
        if not self.cert_present or not self.cert_valid:
            return 25
        if self.is_expired:
            return 20
        if self.days_until_expiry is not None and self.days_until_expiry < 7:
            return 10
        return 0


def _parse_ssl_date(s: str) -> Optional[datetime]:
    """Parse ASN.1 GeneralizedTime as returned by ssl.getpeercert()."""
    try:
        dt = datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _get_cn(rdns_seq) -> Optional[str]:
    for rdns in rdns_seq:
        for attr in rdns:
            if attr[0] == "commonName":
                return attr[1]
    return None


def _get_org(rdns_seq) -> Optional[str]:
    for rdns in rdns_seq:
        for attr in rdns:
            if attr[0] == "organizationName":
                return attr[1]
    return None


async def check_ssl(url: str) -> SSLResult:
    """
    Asynchronously validate the TLS certificate for *url*'s host.
    Uses asyncio.to_thread to avoid blocking the event loop.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return SSLResult(
            host=host, port=port,
            cert_present=False, cert_valid=False,
            subject_cn=None, issuer_o=None,
            not_before=None, not_after=None,
            days_until_expiry=None,
            error="Non-HTTPS scheme — no TLS certificate",
        )

    return await asyncio.to_thread(_check_ssl_blocking, host, port)


def _check_ssl_blocking(host: str, port: int) -> SSLResult:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        subject_cn = _get_cn(cert.get("subject", []))
        issuer_o = _get_org(cert.get("issuer", []))
        not_before = _parse_ssl_date(cert.get("notBefore", ""))
        not_after = _parse_ssl_date(cert.get("notAfter", ""))
        days_until_expiry: Optional[int] = None
        if not_after:
            days_until_expiry = (not_after - datetime.now(tz=timezone.utc)).days

        result = SSLResult(
            host=host, port=port,
            cert_present=True, cert_valid=True,
            subject_cn=subject_cn, issuer_o=issuer_o,
            not_before=not_before, not_after=not_after,
            days_until_expiry=days_until_expiry,
        )
        logger.info(
            "SSL %s:%d — valid, expires in %s days", host, port, days_until_expiry
        )
        return result

    except ssl.SSLCertVerificationError as exc:
        logger.warning("SSL cert verification failed for %s: %s", host, exc)
        return SSLResult(
            host=host, port=port,
            cert_present=True, cert_valid=False,
            subject_cn=None, issuer_o=None,
            not_before=None, not_after=None,
            days_until_expiry=None,
            error=str(exc),
        )
    except (ssl.SSLError, ConnectionRefusedError, OSError, socket.timeout) as exc:
        logger.warning("SSL connection error for %s: %s", host, exc)
        return SSLResult(
            host=host, port=port,
            cert_present=False, cert_valid=False,
            subject_cn=None, issuer_o=None,
            not_before=None, not_after=None,
            days_until_expiry=None,
            error=str(exc),
        )
