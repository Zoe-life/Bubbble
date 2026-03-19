/**
 * Phase 2, Point 3 — Animated Bubble Overlay (< 2 s scanning target)
 *
 * Renders a full-screen overlay with a bubble that:
 *   - Inflates and pulses while the URL scan is running
 *   - Gracefully deflates when the link is safe
 *   - Dramatically bursts when the link is malicious
 *
 * The overlay auto-dismisses after the animation completes on safe links.
 * On malicious links it stays visible until the user acknowledges.
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import "./BubbleOverlay.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BubbleState = "inflating" | "safe" | "danger";

export interface BubbleScanResult {
  safe: boolean;
  /** Human-readable explanation shown beneath the bubble. */
  reason?: string;
  /** Blocked URL (shown on danger state). */
  url?: string;
}

export interface BubbleOverlayProps {
  /** URL currently being scanned. */
  targetUrl: string;
  /**
   * Promise that resolves with the scan result.
   * The overlay transitions automatically when this resolves.
   */
  scanPromise: Promise<BubbleScanResult>;
  /** Called when the overlay has fully closed (safe auto-dismiss or user ack). */
  onDismiss: () => void;
  /** Override the maximum scan wait time in ms (default: 2000). */
  maxScanMs?: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** How long to show the "safe" state before auto-dismissing (ms). */
const SAFE_DISMISS_DELAY_MS = 600;

/** Milliseconds after which we optimistically show "still scanning…" sub-label. */
const SLOW_SCAN_THRESHOLD_MS = 1500;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const BubbleOverlay: React.FC<BubbleOverlayProps> = ({
  targetUrl,
  scanPromise,
  onDismiss,
  maxScanMs = 2000,
}) => {
  const [state, setState] = useState<BubbleState>("inflating");
  const [result, setResult] = useState<BubbleScanResult | null>(null);
  const [slowScan, setSlowScan] = useState(false);
  const dismissTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const slowTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Slow-scan indicator ─────────────────────────────────────────────────
  useEffect(() => {
    slowTimer.current = setTimeout(
      () => setSlowScan(true),
      SLOW_SCAN_THRESHOLD_MS,
    );
    return () => {
      if (slowTimer.current) clearTimeout(slowTimer.current);
    };
  }, []);

  // ── Await scan result ───────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;

    // Safety timeout: treat unknown as safe after maxScanMs
    const safetyTimer = setTimeout(() => {
      if (!cancelled) {
        setResult({ safe: true, reason: "Scan timed out — proceeding." });
        setState("safe");
      }
    }, maxScanMs);

    scanPromise
      .then((res) => {
        if (cancelled) return;
        clearTimeout(safetyTimer);
        if (slowTimer.current) clearTimeout(slowTimer.current);
        setResult(res);
        setState(res.safe ? "safe" : "danger");
      })
      .catch(() => {
        if (cancelled) return;
        clearTimeout(safetyTimer);
        // On error, fail open (safe) to avoid blocking every link
        setResult({ safe: true, reason: "Scan error — proceeding." });
        setState("safe");
      });

    return () => {
      cancelled = true;
      clearTimeout(safetyTimer);
    };
  }, [scanPromise, maxScanMs]);

  // ── Auto-dismiss on safe ────────────────────────────────────────────────
  useEffect(() => {
    if (state === "safe") {
      dismissTimer.current = setTimeout(onDismiss, SAFE_DISMISS_DELAY_MS);
    }
    return () => {
      if (dismissTimer.current) clearTimeout(dismissTimer.current);
    };
  }, [state, onDismiss]);

  // ── Label copy ──────────────────────────────────────────────────────────
  const label = (() => {
    if (state === "inflating")
      return slowScan ? "Still scanning…" : "Checking link…";
    if (state === "safe") return "Link is safe ✓";
    return "Link blocked 🚫";
  })();

  const sub = (() => {
    if (state === "inflating")
      return `Bubbble is scanning ${truncate(targetUrl, 55)}`;
    if (state === "safe") return result?.reason ?? "Taking you there now.";
    return (
      result?.reason ??
      "This link appears malicious. We've blocked it to protect you."
    );
  })();

  const handleProceedAnyway = useCallback(() => {
    // User explicitly overrides the block — open in new tab and dismiss
    if (result?.url) {
      window.open(result.url, "_blank", "noopener,noreferrer");
    }
    onDismiss();
  }, [result, onDismiss]);

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <div className="bubbble-overlay" data-state={state} role="dialog" aria-modal="true" aria-label={label}>
      <div className="bubbble-wrapper">
        <div className="bubbble-sphere" />

        {/* Burst shards — only rendered in danger state */}
        {state === "danger" && (
          <div className="bubbble-shards" aria-hidden="true">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="bubbble-shard" />
            ))}
          </div>
        )}
      </div>

      {/* Scanning dots beneath bubble */}
      {state === "inflating" && (
        <div className="bubbble-scanning-dots" aria-hidden="true">
          <span /><span /><span />
        </div>
      )}

      <p className="bubbble-label">{label}</p>
      <p className="bubbble-sub">{sub}</p>

      {/* Action buttons — only shown on danger state */}
      {state === "danger" && (
        <div className="bubbble-actions">
          <button
            className="bubbble-btn bubbble-btn--primary"
            onClick={onDismiss}
            autoFocus
          >
            Keep me safe
          </button>
          <button
            className="bubbble-btn bubbble-btn--ghost"
            onClick={handleProceedAnyway}
          >
            Proceed anyway
          </button>
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncate(str: string, max: number): string {
  return str.length <= max ? str : str.slice(0, max) + "…";
}

export default BubbleOverlay;
