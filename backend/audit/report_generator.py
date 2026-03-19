"""
Phase 4 — Burst Audit Report Generator

Automatically generates a structured audit report immediately after Bubbble
blocks a link (a "burst" event). The report is:

  1. Stored in the encrypted audit log (AuditLogStore.write)
  2. Returned as a structured AuditReport object for immediate display
  3. Optionally exported to PDF (pdf_export.py) for download / sharing

This module is the single entry point for all post-burst report creation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from backend.audit.audit_log import AuditEntry, AuditLogStore
from backend.url_analysis.risk_scorer import RiskScoreResult, RiskLevel

logger = logging.getLogger(__name__)


# ── Threat category mapping ───────────────────────────────────────────────────

_SIGNAL_TO_CATEGORY: dict[str, str] = {
    "safe_browsing": "malware",
    "virustotal": "malware",
    "phishtank": "phishing",
    "openphish": "phishing",
    "ssl": "credential_harvesting",
    "whois": "newly_registered_domain",
    "redirect_chain": "redirect_abuse",
    "content_preview": "phishing",
}

_CATEGORY_LABELS: dict[str, str] = {
    "phishing": "Phishing",
    "malware": "Malware / Malicious download",
    "credential_harvesting": "Credential harvesting",
    "newly_registered_domain": "Newly registered domain",
    "redirect_abuse": "Redirect chain abuse",
    "unknown": "Unknown threat",
}


def _infer_threat_category(score_result: RiskScoreResult) -> str:
    for signal in score_result.signals:
        cat = _SIGNAL_TO_CATEGORY.get(signal.source)
        if cat:
            return cat
    return "unknown"


# ── Report model ──────────────────────────────────────────────────────────────

@dataclass
class AuditReport:
    entry_id: str
    user_id: int
    created_at: str
    blocked_url: str
    final_url: str
    threat_category: str
    threat_category_label: str
    origin_platform: str
    risk_score: int
    risk_level: str
    signals: list[dict]
    redirect_chain: list[str]
    recommended_action: str
    screenshot_b64: Optional[str] = None

    @property
    def is_malicious(self) -> bool:
        return self.risk_score >= 70


# ── Generator ─────────────────────────────────────────────────────────────────

class AuditReportGenerator:
    """
    Creates, stores, and returns a full audit report after a link is blocked.

    Usage::

        generator = AuditReportGenerator(audit_store)
        report = await generator.generate(
            user_id=42,
            origin_platform="whatsapp",
            score_result=risk_score_result,
        )
    """

    def __init__(self, store: AuditLogStore) -> None:
        self._store = store

    async def generate(
        self,
        user_id: int,
        origin_platform: str,
        score_result: RiskScoreResult,
    ) -> AuditReport:
        """
        Build and persist a full audit report from a RiskScoreResult.
        Returns the report immediately for display in the UI.
        """
        threat_category = _infer_threat_category(score_result)
        threat_label = _CATEGORY_LABELS.get(threat_category, threat_category.replace("_", " ").title())

        signals_dicts = [
            {"source": s.source, "contribution": s.contribution, "detail": s.detail}
            for s in score_result.signals
        ]

        entry = AuditEntry.create(
            user_id=user_id,
            blocked_url=score_result.url,
            final_url=score_result.final_url,
            threat_category=threat_category,
            origin_platform=origin_platform,
            risk_score=score_result.score,
            signals=signals_dicts,
            redirect_chain=score_result.redirect_chain,
            recommended_action=score_result.recommended_action,
            screenshot_b64=score_result.screenshot_b64,
        )

        try:
            await self._store.write(entry)
        except Exception as exc:
            logger.error("Failed to persist audit entry: %s", exc)

        report = AuditReport(
            entry_id=entry.entry_id,
            user_id=user_id,
            created_at=entry.created_at,
            blocked_url=score_result.url,
            final_url=score_result.final_url,
            threat_category=threat_category,
            threat_category_label=threat_label,
            origin_platform=origin_platform,
            risk_score=score_result.score,
            risk_level=score_result.level.value,
            signals=signals_dicts,
            redirect_chain=score_result.redirect_chain,
            recommended_action=score_result.recommended_action,
            screenshot_b64=score_result.screenshot_b64,
        )
        logger.info(
            "Audit report generated: entry_id=%s user=%d score=%d",
            entry.entry_id, user_id, score_result.score,
        )
        return report
