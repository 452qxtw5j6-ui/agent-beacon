// Storage-backed settings with defaults. Lives in chrome.storage.local so it
// survives service-worker suspension.

import { ext } from '../shared/browser.js';
import { DEFAULT_SETTINGS, type Settings, type SiteName } from '../shared/types.js';
import { parseSettingsPatch } from '../shared/validate.js';

const KEY = 'settings';

/**
 * Merge stored settings over the defaults, keeping only stored values that
 * still validate. A value saved by an older build that is no longer allowed
 * (an endpoint off loopback, say) falls back to its default.
 */
export function resolveSettings(stored: unknown): Settings {
  const s = (stored ?? {}) as Partial<Settings>;
  const out: Settings = { ...DEFAULT_SETTINGS, sites: { ...DEFAULT_SETTINGS.sites } };
  for (const key of ['enabled', 'retention', 'endpoint'] as const) {
    if (!(key in s)) continue;
    const r = parseSettingsPatch({ [key]: s[key] });
    if (r.ok) Object.assign(out, r.patch);
  }
  if (s.sites && typeof s.sites === 'object') {
    for (const site of Object.keys(out.sites) as SiteName[]) {
      if (typeof s.sites[site] === 'boolean') out.sites[site] = s.sites[site];
    }
  }
  return out;
}

export async function getSettings(): Promise<Settings> {
  const got = await ext.storage.local.get(KEY);
  return resolveSettings(got[KEY]);
}

/** Apply an already-validated patch (see parseSettingsPatch). */
export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const current = await getSettings();
  const next: Settings = {
    ...current,
    ...patch,
    sites: { ...current.sites, ...(patch.sites ?? {}) },
  };
  await ext.storage.local.set({ [KEY]: next });
  return next;
}

export function siteEnabled(settings: Settings, site: SiteName): boolean {
  return settings.enabled && settings.sites[site] !== false;
}
