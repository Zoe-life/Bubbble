/**
 * Phase 2 — Settings Panel (React popup)
 *
 * Allows users to configure:
 *  - Sensitivity level (low / medium / high)
 *  - Custom domain whitelist
 *  - Custom domain blacklist
 *  - Desktop notification toggle
 *  - Offline mode toggle
 */

import React, { useEffect, useState } from 'react';
import type { ExtensionSettings, SensitivityLevel } from '../types.js';

const DEFAULT_SETTINGS: ExtensionSettings = {
  sensitivity: 'medium',
  whitelist: [],
  blacklist: [],
  notificationsEnabled: true,
  offlineModeEnabled: true,
};

export function Settings(): JSX.Element {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);
  const [whitelistInput, setWhitelistInput] = useState('');
  const [blacklistInput, setBlacklistInput] = useState('');

  useEffect(() => {
    chrome.storage.sync.get('settings', (stored) => {
      if (stored.settings) {
        setSettings({ ...DEFAULT_SETTINGS, ...stored.settings });
      }
    });
  }, []);

  function save(updated: ExtensionSettings): void {
    chrome.storage.sync.set({ settings: updated }, () => {
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    });
  }

  function updateField<K extends keyof ExtensionSettings>(
    key: K,
    value: ExtensionSettings[K],
  ): void {
    const updated = { ...settings, [key]: value };
    setSettings(updated);
    save(updated);
  }

  function addToList(
    list: 'whitelist' | 'blacklist',
    input: string,
    setInput: (v: string) => void,
  ): void {
    const domain = input.trim().toLowerCase();
    if (!domain || settings[list].includes(domain)) return;
    updateField(list, [...settings[list], domain]);
    setInput('');
  }

  function removeFromList(list: 'whitelist' | 'blacklist', domain: string): void {
    updateField(
      list,
      settings[list].filter((d) => d !== domain),
    );
  }

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>⚪ Bubbble Settings</h1>

      {/* ── Sensitivity ───────────────────────────────────────── */}
      <section style={styles.section}>
        <label style={styles.label}>Scan sensitivity</label>
        <div style={styles.radioGroup}>
          {(['low', 'medium', 'high'] as SensitivityLevel[]).map((lvl) => (
            <label key={lvl} style={styles.radioLabel}>
              <input
                type="radio"
                name="sensitivity"
                value={lvl}
                checked={settings.sensitivity === lvl}
                onChange={() => updateField('sensitivity', lvl)}
              />
              {lvl.charAt(0).toUpperCase() + lvl.slice(1)}
            </label>
          ))}
        </div>
        <p style={styles.hint}>
          {settings.sensitivity === 'low' && 'Only blocks confirmed malicious links (fewer false positives).'}
          {settings.sensitivity === 'medium' && 'Blocks malicious and suspicious links (recommended).'}
          {settings.sensitivity === 'high' && 'Warns on any unknown or newly-registered domain.'}
        </p>
      </section>

      {/* ── Whitelist ─────────────────────────────────────────── */}
      <section style={styles.section}>
        <label style={styles.label}>Trusted domains (whitelist)</label>
        <div style={styles.inputRow}>
          <input
            style={styles.input}
            type="text"
            placeholder="example.com"
            value={whitelistInput}
            onChange={(e) => setWhitelistInput(e.target.value)}
            onKeyDown={(e) =>
              e.key === 'Enter' && addToList('whitelist', whitelistInput, setWhitelistInput)
            }
          />
          <button
            style={styles.addBtn}
            onClick={() => addToList('whitelist', whitelistInput, setWhitelistInput)}
          >
            Add
          </button>
        </div>
        <DomainList
          items={settings.whitelist}
          onRemove={(d) => removeFromList('whitelist', d)}
          colour="#22c55e"
        />
      </section>

      {/* ── Blacklist ─────────────────────────────────────────── */}
      <section style={styles.section}>
        <label style={styles.label}>Always block (blacklist)</label>
        <div style={styles.inputRow}>
          <input
            style={styles.input}
            type="text"
            placeholder="evil-domain.com"
            value={blacklistInput}
            onChange={(e) => setBlacklistInput(e.target.value)}
            onKeyDown={(e) =>
              e.key === 'Enter' && addToList('blacklist', blacklistInput, setBlacklistInput)
            }
          />
          <button
            style={styles.addBtn}
            onClick={() => addToList('blacklist', blacklistInput, setBlacklistInput)}
          >
            Add
          </button>
        </div>
        <DomainList
          items={settings.blacklist}
          onRemove={(d) => removeFromList('blacklist', d)}
          colour="#ef4444"
        />
      </section>

      {/* ── Toggles ───────────────────────────────────────────── */}
      <section style={styles.section}>
        <Toggle
          label="Desktop notifications"
          value={settings.notificationsEnabled}
          onChange={(v) => updateField('notificationsEnabled', v)}
        />
        <Toggle
          label="Offline mode (cached threat lists)"
          value={settings.offlineModeEnabled}
          onChange={(v) => updateField('offlineModeEnabled', v)}
        />
      </section>

      {saved && <p style={styles.savedMsg}>✓ Saved</p>}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function DomainList({
  items,
  onRemove,
  colour,
}: {
  items: string[];
  onRemove: (d: string) => void;
  colour: string;
}): JSX.Element {
  if (!items.length) return <></>;
  return (
    <ul style={styles.chipList}>
      {items.map((d) => (
        <li key={d} style={{ ...styles.chip, borderColor: colour }}>
          {d}
          <button style={styles.chipRemove} onClick={() => onRemove(d)} aria-label={`Remove ${d}`}>
            ×
          </button>
        </li>
      ))}
    </ul>
  );
}

function Toggle({
  label,
  value,
  onChange,
}: {
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
}): JSX.Element {
  return (
    <label style={styles.toggleLabel}>
      <input
        type="checkbox"
        checked={value}
        onChange={(e) => onChange(e.target.checked)}
        style={{ marginRight: 8 }}
      />
      {label}
    </label>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles: Record<string, React.CSSProperties> = {
  container: { width: 340, padding: '16px 20px', fontFamily: 'system-ui, sans-serif', fontSize: 13 },
  title: { fontSize: 18, fontWeight: 700, margin: '0 0 16px', color: '#1e40af' },
  section: { marginBottom: 18 },
  label: { display: 'block', fontWeight: 600, marginBottom: 6, color: '#374151' },
  radioGroup: { display: 'flex', gap: 16 },
  radioLabel: { display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' },
  hint: { fontSize: 11, color: '#6b7280', marginTop: 4 },
  inputRow: { display: 'flex', gap: 6 },
  input: { flex: 1, padding: '6px 10px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 },
  addBtn: { padding: '6px 12px', background: '#1e40af', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 13 },
  chipList: { listStyle: 'none', margin: '8px 0 0', padding: 0, display: 'flex', flexWrap: 'wrap', gap: 6 },
  chip: { display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px', border: '1px solid', borderRadius: 12, fontSize: 12, color: '#374151' },
  chipRemove: { background: 'none', border: 'none', cursor: 'pointer', color: '#9ca3af', fontWeight: 700, padding: 0, lineHeight: 1 },
  toggleLabel: { display: 'flex', alignItems: 'center', cursor: 'pointer', marginBottom: 8, color: '#374151' },
  savedMsg: { textAlign: 'center', color: '#22c55e', fontWeight: 600, marginTop: 4 },
};
