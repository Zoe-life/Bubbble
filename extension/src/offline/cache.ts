/**
 * Phase 2 — Offline Threat Cache Manager
 *
 * Downloads a compact threat list from the Bubbble CDN and stores it in
 * chrome.storage.local so the extension can detect obviously malicious domains
 * without network access (degraded mode).
 *
 * Cache format (stored under key "offlineThreatCache"):
 *   { domains: { [sha256Hex]: { threatType, addedAt } }, updatedAt: number }
 *
 * The cache is refreshed every 15 minutes by the background alarm.
 */

import type { CacheEntry } from '../types.js';

const CACHE_LIST_URL = 'https://cdn.bubbble.com/threat-cache/v1/compact.json';
const STORAGE_KEY = 'offlineThreatCache';
const MAX_CACHE_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

interface CacheStore {
  domains: Record<string, CacheEntry>;  // sha256(domain) → CacheEntry
  updatedAt: number;
}

export class OfflineCacheManager {
  private _cache: CacheStore = { domains: {}, updatedAt: 0 };

  /** Load the cache from chrome.storage.local into memory. */
  async loadFromStorage(): Promise<void> {
    const stored = await chrome.storage.local.get(STORAGE_KEY);
    if (stored[STORAGE_KEY]) {
      this._cache = stored[STORAGE_KEY] as CacheStore;
    }
  }

  /** Download a fresh threat list from the CDN and persist it. */
  async refresh(): Promise<void> {
    try {
      const resp = await fetch(CACHE_LIST_URL, {
        cache: 'no-store',
        signal: AbortSignal.timeout(10_000),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

      const data = (await resp.json()) as {
        domains: Record<string, { threatType: string }>;
      };

      const domains: Record<string, CacheEntry> = {};
      for (const [hash, meta] of Object.entries(data.domains)) {
        domains[hash] = { threatType: meta.threatType, addedAt: Date.now() };
      }

      this._cache = { domains, updatedAt: Date.now() };
      await chrome.storage.local.set({ [STORAGE_KEY]: this._cache });
      console.log(
        `[Bubbble] Offline cache refreshed: ${Object.keys(domains).length} entries`,
      );
    } catch (err) {
      console.warn('[Bubbble] Offline cache refresh failed:', err);
    }
  }

  /**
   * Check whether a URL's domain is in the offline threat list.
   * Returns a CacheEntry if found, null otherwise.
   */
  async check(url: string): Promise<CacheEntry | null> {
    if (this._isCacheExpired()) {
      await this.loadFromStorage();
    }

    let hostname: string;
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      return null;
    }

    const hash = await sha256Hex(hostname);
    return this._cache.domains[hash] ?? null;
  }

  private _isCacheExpired(): boolean {
    return Date.now() - this._cache.updatedAt > MAX_CACHE_AGE_MS;
  }
}

// ── Crypto helper ─────────────────────────────────────────────────────────────

async function sha256Hex(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}
