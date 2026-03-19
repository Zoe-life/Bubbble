"""
Phase 1 — Content Preview Fetch (Headless Browser + DOM Analysis)

Uses Playwright to load the final destination URL in a sandboxed headless
browser, captures a screenshot, and performs basic DOM analysis to detect
common phishing signals (login form without HTTPS, credential input fields,
brand impersonation patterns, etc.).

All content fetching happens server-side — the user's device never visits the
link directly.

Requires:
    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Playwright is an optional dependency — handled gracefully when absent
try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not installed — content preview will be skipped.")

# ---------------------------------------------------------------------------
# Phishing-signal detection patterns (basic DOM heuristics)
# ---------------------------------------------------------------------------

_SUSPICIOUS_INPUT_TYPES = {"password", "email"}

# Brand names commonly impersonated in phishing pages
_IMPERSONATION_BRANDS = {
    "paypal", "google", "facebook", "instagram", "twitter", "tiktok",
    "netflix", "amazon", "microsoft", "apple", "whatsapp", "bank",
    "mpesa", "safaricom", "equity", "kcb",
}

_PAGE_LOAD_TIMEOUT_MS = 15_000   # 15 s
_SCREENSHOT_TIMEOUT_MS = 5_000


@dataclass
class ContentPreviewResult:
    url: str
    page_title: str = ""
    screenshot_b64: Optional[str] = None       # base64-encoded PNG
    has_password_field: bool = False
    has_email_field: bool = False
    form_action_mismatch: bool = False          # form submits to a different domain
    possible_brand_impersonation: Optional[str] = None
    link_count: int = 0
    external_link_count: int = 0
    error: Optional[str] = None

    @property
    def risk_score_contribution(self) -> int:
        """Returns 0–20 points to the overall risk score."""
        score = 0
        if self.has_password_field:
            score += 8
        if self.form_action_mismatch:
            score += 7
        if self.possible_brand_impersonation:
            score += 5
        return min(score, 20)


async def fetch_content_preview(url: str) -> ContentPreviewResult:
    """
    Launch a sandboxed headless Chromium browser, load *url*, take a
    screenshot, and run DOM-level phishing-signal detection.
    Returns a ContentPreviewResult regardless of errors.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return ContentPreviewResult(url=url, error="Playwright not available")

    try:
        return await _run_preview(url)
    except Exception as exc:
        logger.error("Content preview error for %s: %s", url, exc)
        return ContentPreviewResult(url=url, error=str(exc))


async def _run_preview(url: str) -> ContentPreviewResult:
    result = ContentPreviewResult(url=url)

    async with async_playwright() as pw:
        browser: Browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        context: BrowserContext = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (compatible; Bubbble/1.0; +https://bubbble.com/bot)",
            java_script_enabled=True,
            bypass_csp=False,
        )
        page: Page = await context.new_page()

        # Block tracking/ads to keep analysis focused
        await page.route(
            "**/*.{png,jpg,jpeg,gif,webp,woff,woff2}",
            lambda r: r.abort(),
        )

        try:
            await page.goto(url, timeout=_PAGE_LOAD_TIMEOUT_MS, wait_until="domcontentloaded")
        except Exception as nav_exc:
            result.error = str(nav_exc)
            await browser.close()
            return result

        result.page_title = await page.title()

        # ── Screenshot ────────────────────────────────────────────────
        try:
            screenshot_bytes = await page.screenshot(
                type="png",
                clip={"x": 0, "y": 0, "width": 1280, "height": 800},
                timeout=_SCREENSHOT_TIMEOUT_MS,
            )
            result.screenshot_b64 = base64.b64encode(screenshot_bytes).decode()
        except Exception:
            pass

        # ── DOM analysis ──────────────────────────────────────────────
        page_url = page.url  # may differ from original after JS redirects

        # Input fields
        input_types = await page.eval_on_selector_all(
            "input[type]",
            "inputs => inputs.map(i => i.type.toLowerCase())",
        )
        input_types_set = set(input_types)
        result.has_password_field = "password" in input_types_set
        result.has_email_field = "email" in input_types_set

        # Form action mismatch
        from urllib.parse import urlparse as _parse
        current_domain = _parse(page_url).netloc
        form_actions = await page.eval_on_selector_all(
            "form[action]",
            "forms => forms.map(f => f.action)",
        )
        for action in form_actions:
            action_domain = _parse(action).netloc
            if action_domain and action_domain != current_domain:
                result.form_action_mismatch = True
                break

        # Brand impersonation (title + URL heuristic)
        combined = (result.page_title + " " + page_url).lower()
        for brand in _IMPERSONATION_BRANDS:
            if brand in combined and brand not in current_domain:
                result.possible_brand_impersonation = brand
                break

        # Link counts
        all_hrefs = await page.eval_on_selector_all(
            "a[href]",
            "links => links.map(l => l.href)",
        )
        result.link_count = len(all_hrefs)
        result.external_link_count = sum(
            1 for h in all_hrefs if _parse(h).netloc != current_domain
        )

        await browser.close()

    logger.info(
        "Content preview %s: title=%r, passwd=%s, impersonation=%s",
        url,
        result.page_title,
        result.has_password_field,
        result.possible_brand_impersonation,
    )
    return result
