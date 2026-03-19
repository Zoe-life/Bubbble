/**
 * Phase 2 — Bubbble Content Script
 *
 * Intercepts every link click (and keyboard activation) on any page,
 * sends the URL to the background service worker for scanning, and
 * either injects the BubbleOverlay component (for scanning / blocking)
 * or releases the navigation (for safe links).
 *
 * Works on all URLs matched by the manifest content_scripts rule.
 */

import type { ScanRequest, ScanResponse } from './types.js';

const MAX_SCAN_MS = 2000; // fail-open after 2 s

// ── Link interception ─────────────────────────────────────────────────────────

document.addEventListener('click', handleClick, { capture: true });
document.addEventListener('keydown', handleKeydown, { capture: true });

function handleClick(event: MouseEvent): void {
  const anchor = closestAnchor(event.target as Element);
  if (!anchor) return;

  const href = resolveHref(anchor);
  if (!href || isInternalOrExtensionUrl(href)) return;

  event.preventDefault();
  event.stopImmediatePropagation();
  triggerScan(href);
}

function handleKeydown(event: KeyboardEvent): void {
  if (event.key !== 'Enter') return;
  const anchor = closestAnchor(event.target as Element);
  if (!anchor) return;

  const href = resolveHref(anchor);
  if (!href || isInternalOrExtensionUrl(href)) return;

  event.preventDefault();
  event.stopImmediatePropagation();
  triggerScan(href);
}

function closestAnchor(el: Element | null): HTMLAnchorElement | null {
  if (!el) return null;
  const a = el.closest('a');
  return a instanceof HTMLAnchorElement ? a : null;
}

function resolveHref(anchor: HTMLAnchorElement): string {
  try {
    return new URL(anchor.href, window.location.href).toString();
  } catch {
    return '';
  }
}

function isInternalOrExtensionUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const scheme = parsed.protocol;
    if (
      scheme === 'javascript:' ||
      scheme === 'data:' ||
      scheme === 'vbscript:' ||
      scheme === 'chrome-extension:' ||
      scheme === 'moz-extension:' ||
      scheme === 'mailto:'
    ) {
      return true;
    }
    return parsed.hostname === window.location.hostname;
  } catch {
    return true;
  }
}

// ── Scan & overlay orchestration ──────────────────────────────────────────────

async function triggerScan(url: string): Promise<void> {
  // Show animated bubble overlay immediately
  showOverlay(url);

  const req: ScanRequest = { url };

  const scanPromise = new Promise<ScanResponse>((resolve) => {
    chrome.runtime.sendMessage({ type: 'SCAN_URL', payload: req }, (response) => {
      resolve(response ?? { url, safe: true, score: 0, source: 'no_response' });
    });
  });

  const timeoutPromise = new Promise<ScanResponse>((resolve) =>
    setTimeout(
      () => resolve({ url, safe: true, score: 0, source: 'timeout_fallback' }),
      MAX_SCAN_MS,
    ),
  );

  const result = await Promise.race([scanPromise, timeoutPromise]);
  handleScanResult(result);
}

// ── Listen for result pushed from background (alternative path) ───────────────

chrome.runtime.onMessage.addListener(
  (message: { type: string; payload?: ScanResponse }) => {
    if (message.type === 'SCAN_RESULT' && message.payload) {
      handleScanResult(message.payload);
    }
  },
);

function handleScanResult(result: ScanResponse): void {
  if (result.safe) {
    dismissOverlayAsSafe(result.url);
  } else {
    showOverlayAsDanger(result);
  }
}

// ── Overlay injection ─────────────────────────────────────────────────────────

const OVERLAY_ID = 'bubbble-overlay-root';

function showOverlay(url: string): void {
  removeOverlay();
  const root = document.createElement('div');
  root.id = OVERLAY_ID;
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-modal', 'true');
  root.setAttribute('aria-label', 'Bubbble scanning link…');
  root.style.cssText = overlayBaseStyles();
  root.innerHTML = buildOverlayHTML('scanning', url);
  document.documentElement.appendChild(root);
}

function dismissOverlayAsSafe(url: string): void {
  const root = document.getElementById(OVERLAY_ID);
  if (!root) {
    // No overlay shown (e.g. timeout took over) — navigate directly
    window.location.href = url;
    return;
  }
  root.innerHTML = buildOverlayHTML('safe', url);
  // Auto-navigate after brief safe animation
  setTimeout(() => {
    removeOverlay();
    window.location.href = url;
  }, 600);
}

function showOverlayAsDanger(result: ScanResponse): void {
  const root = document.getElementById(OVERLAY_ID);
  if (!root) return;
  root.innerHTML = buildOverlayHTML('danger', result.url, result);
  root.querySelector('#bubbble-proceed')?.addEventListener('click', () => {
    removeOverlay();
    window.location.href = result.url;
  });
  root.querySelector('#bubbble-cancel')?.addEventListener('click', () => {
    removeOverlay();
  });
}

function removeOverlay(): void {
  document.getElementById(OVERLAY_ID)?.remove();
}

function overlayBaseStyles(): string {
  return [
    'position:fixed',
    'inset:0',
    'z-index:2147483647',
    'display:flex',
    'align-items:center',
    'justify-content:center',
    'background:rgba(0,0,0,0.72)',
    'font-family:system-ui,sans-serif',
  ].join(';');
}

function buildOverlayHTML(
  state: 'scanning' | 'safe' | 'danger',
  url: string,
  result?: ScanResponse,
): string {
  const truncatedUrl = url.length > 60 ? url.slice(0, 57) + '…' : url;

  if (state === 'scanning') {
    return `
      <div style="text-align:center;color:#fff">
        <div style="width:80px;height:80px;margin:0 auto 20px;border-radius:50%;
                    background:radial-gradient(circle at 35% 35%,#a0d8ff,#1e90ff 60%,#003d7a);
                    animation:bubbble-pulse 1.2s ease-in-out infinite;box-shadow:0 0 0 0 rgba(30,144,255,.6)">
        </div>
        <p style="font-size:18px;font-weight:600">Scanning link…</p>
        <p style="font-size:13px;opacity:.75;max-width:320px;margin:8px auto 0;word-break:break-all">${escapeHtml(truncatedUrl)}</p>
        <style>
          @keyframes bubbble-pulse{0%,100%{transform:scale(1);box-shadow:0 0 0 0 rgba(30,144,255,.6)}50%{transform:scale(1.12);box-shadow:0 0 0 16px rgba(30,144,255,0)}}
          @media(prefers-reduced-motion:reduce){.bubbble-bubble{animation:none!important}}
        </style>
      </div>`;
  }

  if (state === 'safe') {
    return `
      <div style="text-align:center;color:#fff">
        <div style="width:80px;height:80px;margin:0 auto 20px;border-radius:50%;
                    background:radial-gradient(circle at 35% 35%,#afffb6,#22c55e 60%,#145c2e);
                    animation:bubbble-safe-shrink .6s ease-in forwards">
        </div>
        <p style="font-size:18px;font-weight:600">✓ Link is safe</p>
        <style>
          @keyframes bubbble-safe-shrink{0%{transform:scale(1.1);opacity:1}100%{transform:scale(0);opacity:0}}
        </style>
      </div>`;
  }

  // danger
  const threatLabel = result?.threatType ?? 'Malicious link';
  return `
    <div style="text-align:center;color:#fff;max-width:400px;padding:24px">
      <div style="width:80px;height:80px;margin:0 auto 20px;border-radius:50%;
                  background:radial-gradient(circle at 35% 35%,#ffb3b3,#ef4444 60%,#7f1d1d);
                  animation:bubbble-burst .4s ease-out forwards">
      </div>
      <p style="font-size:20px;font-weight:700;color:#ef4444">⚠ Danger — link blocked</p>
      <p style="font-size:14px;margin:8px 0">${escapeHtml(threatLabel)}</p>
      <p style="font-size:12px;opacity:.7;margin:0 0 20px;word-break:break-all">${escapeHtml(truncatedUrl)}</p>
      <div style="display:flex;gap:12px;justify-content:center">
        <button id="bubbble-cancel"
          style="padding:10px 20px;background:#22c55e;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600">
          Keep me safe
        </button>
        <button id="bubbble-proceed"
          style="padding:10px 20px;background:transparent;color:#fff;border:1px solid rgba(255,255,255,.4);border-radius:8px;cursor:pointer;font-size:14px">
          Proceed anyway
        </button>
      </div>
      <style>
        @keyframes bubbble-burst{0%{transform:scale(1.2)}60%{transform:scale(.8)}100%{transform:scale(1)}}
      </style>
    </div>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
