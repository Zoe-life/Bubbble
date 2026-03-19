/**
 * Phase 2 — Bubbble Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 *  - Receives SCAN_URL messages from the content script
 *  - Checks the offline cached threat list first (zero-latency)
 *  - Falls back to the Bubbble cloud API for a full scan
 *  - Broadcasts results back to the originating tab
 *  - Manages the 15-minute offline cache refresh alarm
 *  - Handles extension settings persistence
 */

import { OfflineCacheManager } from '../offline/cache.js';
import type { ScanRequest, ScanResponse, ExtensionSettings } from '../types.js';

const API_BASE = 'https://api.bubbble.com/v1';
const CACHE_REFRESH_ALARM = 'threat-cache-refresh';
const CACHE_REFRESH_INTERVAL_MINUTES = 15;

const offlineCache = new OfflineCacheManager();

// ── Startup ──────────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  await initDefaultSettings();
  await offlineCache.refresh();
  scheduleOfflineCacheRefresh();
  console.log('[Bubbble] Extension installed / updated.');
});

chrome.runtime.onStartup.addListener(async () => {
  await offlineCache.loadFromStorage();
  scheduleOfflineCacheRefresh();
});

// ── Alarm: offline cache refresh ─────────────────────────────────────────────

function scheduleOfflineCacheRefresh(): void {
  chrome.alarms.create(CACHE_REFRESH_ALARM, {
    delayInMinutes: CACHE_REFRESH_INTERVAL_MINUTES,
    periodInMinutes: CACHE_REFRESH_INTERVAL_MINUTES,
  });
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === CACHE_REFRESH_ALARM) {
    console.log('[Bubbble] Refreshing offline threat cache…');
    await offlineCache.refresh();
  }
});

// ── Message handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (
    message: { type: string; payload?: unknown },
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: ScanResponse) => void,
  ) => {
    if (message.type === 'SCAN_URL') {
      const req = message.payload as ScanRequest;
      handleScanRequest(req, sender.tab?.id)
        .then(sendResponse)
        .catch((err) => {
          console.error('[Bubbble] Scan error:', err);
          // Fail open — allow navigation
          sendResponse({ url: req.url, safe: true, score: 0, source: 'error_fallback' });
        });
      return true; // keep message channel open for async response
    }
    return false;
  },
);

// ── Core scan logic ──────────────────────────────────────────────────────────

async function handleScanRequest(
  req: ScanRequest,
  tabId?: number,
): Promise<ScanResponse> {
  const settings = await getSettings();

  // 1. Offline cache check (instant)
  const offlineHit = await offlineCache.check(req.url);
  if (offlineHit) {
    const response: ScanResponse = {
      url: req.url,
      safe: false,
      score: 100,
      threatType: offlineHit.threatType,
      source: 'offline_cache',
    };
    if (tabId !== undefined) notifyTab(tabId, response);
    return response;
  }

  // 2. Cloud API scan
  try {
    const response = await callScanApi(req.url, settings);
    if (tabId !== undefined) notifyTab(tabId, response);
    return response;
  } catch {
    // Network error — degrade gracefully
    return { url: req.url, safe: true, score: 0, source: 'degraded_offline' };
  }
}

async function callScanApi(url: string, settings: ExtensionSettings): Promise<ScanResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  const resp = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, sensitivity: settings.sensitivity }),
    signal: controller.signal,
  });
  clearTimeout(timeout);

  if (!resp.ok) throw new Error(`API error ${resp.status}`);
  return resp.json() as Promise<ScanResponse>;
}

function notifyTab(tabId: number, result: ScanResponse): void {
  chrome.tabs.sendMessage(tabId, { type: 'SCAN_RESULT', payload: result }).catch(() => {
    // Tab may have navigated away — safe to ignore
  });
}

// ── Settings ─────────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS: ExtensionSettings = {
  sensitivity: 'medium',
  whitelist: [],
  blacklist: [],
  notificationsEnabled: true,
  offlineModeEnabled: true,
};

async function initDefaultSettings(): Promise<void> {
  const stored = await chrome.storage.sync.get('settings');
  if (!stored.settings) {
    await chrome.storage.sync.set({ settings: DEFAULT_SETTINGS });
  }
}

async function getSettings(): Promise<ExtensionSettings> {
  const stored = await chrome.storage.sync.get('settings');
  return { ...DEFAULT_SETTINGS, ...(stored.settings ?? {}) };
}
