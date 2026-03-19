"""
Phase 1 — Risk Scoring Model (0–100)

Aggregates signals from all URL analysis sources into a single normalised
risk score:

  Source                          Max contribution
  ─────────────────────────────── ────────────────
  Google Safe Browsing match      40
  VirusTotal detections           25
  PhishTank / OpenPhish match     35
  SSL/TLS certificate issues      25
  WHOIS domain age                30
  Redirect chain depth            10
  Content preview signals         20
  ─────────────────────────────────
  Raw total (capped at 100)      100

A score of 0–30  → SAFE
A score of 31–69 → SUSPICIOUS
A score of 70+   → MALICIOUS
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from backend.url_analysis.content_preview import ContentPreviewResult
from backend.url_analysis.google_safe_browsing import SafeBrowsingHit
from backend.url_analysis.phishtank_openphish import PhishHit
from backend.url_analysis.redirect_chain import RedirectChainResult
from backend.url_analysis.ssl_check import SSLResult
from backend.url_analysis.virustotal import VirusTotalResult
from backend.url_analysis.whois_check import WhoisResult

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class RiskSignal:
    source: str
    contribution: int
    detail: str


@dataclass
class RiskScoreResult:
    url: str
    final_url: str
    score: int                          # 0–100
    level: RiskLevel
    signals: list[RiskSignal] = field(default_factory=list)
    screenshot_b64: Optional[str] = None
    redirect_chain: list[str] = field(default_factory=list)
    recommended_action: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.level == RiskLevel.MALICIOUS

    @property
    def is_suspicious(self) -> bool:
        return self.level == RiskLevel.SUSPICIOUS


def _level_from_score(score: int) -> RiskLevel:
    if score >= 70:
        return RiskLevel.MALICIOUS
    if score >= 31:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.SAFE


def _recommended_action(level: RiskLevel, signals: list[RiskSignal]) -> str:
    if level == RiskLevel.SAFE:
        return "This link appears safe. Proceeding to destination."
    sources = {s.source for s in signals}
    if level == RiskLevel.MALICIOUS:
        if "phishtank" in sources or "openphish" in sources:
            return (
                "This link is a known phishing page. Do NOT enter any credentials. "
                "If you already clicked it on another device, change your passwords immediately."
            )
        if "safe_browsing" in sources:
            return (
                "Google Safe Browsing has flagged this link as dangerous. "
                "Do not visit it and report it to the platform you received it from."
            )
        return (
            "This link has been blocked as malicious. "
            "Do not proceed and report it to the platform you received it from."
        )
    return (
        "This link looks suspicious. Proceed only if you fully trust the sender, "
        "and never enter passwords or personal information."
    )


def calculate_risk_score(
    url: str,
    *,
    safe_browsing_hit: Optional[SafeBrowsingHit] = None,
    vt_result: Optional[VirusTotalResult] = None,
    phish_hit: Optional[PhishHit] = None,
    ssl_result: Optional[SSLResult] = None,
    whois_result: Optional[WhoisResult] = None,
    redirect_result: Optional[RedirectChainResult] = None,
    content_result: Optional[ContentPreviewResult] = None,
) -> RiskScoreResult:
    """
    Combine all analysis signals into a single 0–100 risk score.
    All inputs are optional — missing signals contribute 0 points.
    """
    signals: list[RiskSignal] = []
    raw_score = 0

    final_url = url
    redirect_chain: list[str] = []
    screenshot_b64: Optional[str] = None

    # ── Google Safe Browsing (max 40) ────────────────────────────────
    if safe_browsing_hit:
        contrib = 40
        raw_score += contrib
        signals.append(RiskSignal(
            source="safe_browsing",
            contribution=contrib,
            detail=f"Threat type: {safe_browsing_hit.threat_type}",
        ))

    # ── VirusTotal (max 25) ──────────────────────────────────────────
    if vt_result:
        malicious = vt_result.stats.malicious
        suspicious = vt_result.stats.suspicious
        # Scale: every malicious engine = 2 pts, suspicious = 1 pt, capped at 25
        contrib = min(malicious * 2 + suspicious, 25)
        if contrib > 0:
            raw_score += contrib
            signals.append(RiskSignal(
                source="virustotal",
                contribution=contrib,
                detail=f"{vt_result.detection_ratio} engines flagged",
            ))

    # ── PhishTank / OpenPhish (max 35) ───────────────────────────────
    if phish_hit:
        contrib = 35
        raw_score += contrib
        signals.append(RiskSignal(
            source=phish_hit.source,
            contribution=contrib,
            detail=f"Listed in {phish_hit.source}",
        ))

    # ── SSL/TLS (max 25) ─────────────────────────────────────────────
    if ssl_result:
        contrib = ssl_result.risk_score_contribution
        if contrib > 0:
            raw_score += contrib
            signals.append(RiskSignal(
                source="ssl",
                contribution=contrib,
                detail=ssl_result.error or ("Expired" if ssl_result.is_expired else "Invalid cert"),
            ))

    # ── WHOIS domain age (max 30) ────────────────────────────────────
    if whois_result:
        contrib = whois_result.risk_score_contribution
        if contrib > 0:
            raw_score += contrib
            signals.append(RiskSignal(
                source="whois",
                contribution=contrib,
                detail=f"Domain age: {whois_result.age_days} days ({whois_result.risk_label})",
            ))

    # ── Redirect chain (max 10) ──────────────────────────────────────
    if redirect_result:
        final_url = redirect_result.final_url
        redirect_chain = [h.url for h in redirect_result.hops]
        depth = redirect_result.chain_length
        # 2 pts per domain crossing, capped at 10
        contrib = min(len(redirect_result.crossed_domains) * 2, 10)
        if contrib > 0:
            raw_score += contrib
            signals.append(RiskSignal(
                source="redirect_chain",
                contribution=contrib,
                detail=f"{depth} hop(s) through {len(redirect_result.crossed_domains)} domain(s)",
            ))

    # ── Content preview (max 20) ─────────────────────────────────────
    if content_result:
        screenshot_b64 = content_result.screenshot_b64
        contrib = content_result.risk_score_contribution
        if contrib > 0:
            raw_score += contrib
            details = []
            if content_result.has_password_field:
                details.append("password field detected")
            if content_result.form_action_mismatch:
                details.append("form submits to different domain")
            if content_result.possible_brand_impersonation:
                details.append(f"possible {content_result.possible_brand_impersonation} impersonation")
            signals.append(RiskSignal(
                source="content_preview",
                contribution=contrib,
                detail=", ".join(details),
            ))

    score = min(raw_score, 100)
    level = _level_from_score(score)

    logger.info(
        "Risk score for %s: %d (%s), signals: %s",
        url, score, level.value,
        [(s.source, s.contribution) for s in signals],
    )

    return RiskScoreResult(
        url=url,
        final_url=final_url,
        score=score,
        level=level,
        signals=signals,
        screenshot_b64=screenshot_b64,
        redirect_chain=redirect_chain,
        recommended_action=_recommended_action(level, signals),
    )
