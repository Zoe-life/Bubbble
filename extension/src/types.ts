/**
 * Phase 2 — Shared TypeScript type definitions for the Bubbble extension.
 */

export type SensitivityLevel = 'low' | 'medium' | 'high';

export interface ScanRequest {
  url: string;
}

export interface ScanResponse {
  url: string;
  safe: boolean;
  score: number;             // 0–100
  threatType?: string;       // e.g. "SOCIAL_ENGINEERING"
  source: string;            // e.g. "cloud_api" | "offline_cache" | "timeout_fallback"
  redirectChain?: string[];
  recommendedAction?: string;
}

export interface ExtensionSettings {
  sensitivity: SensitivityLevel;
  whitelist: string[];
  blacklist: string[];
  notificationsEnabled: boolean;
  offlineModeEnabled: boolean;
}

export interface CacheEntry {
  threatType: string;
  addedAt: number; // epoch ms
}
