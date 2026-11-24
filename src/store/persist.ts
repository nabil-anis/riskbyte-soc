import type { EngineData, Role } from '../engine/types';

export const KEYS = {
  state: 'riskbyte.state.v1',
  settings: 'riskbyte.settings.v1',
  session: 'riskbyte.session.v1',
  checklist: 'riskbyte.checklist.v1',
  engine: 'riskbyte.engine.v1',
};

export interface Settings {
  apiKey: string;
  model: string;
  speed: 'fast' | 'normal' | 'slow';
  rememberEngine: boolean;
  terminalAutoOpened: boolean;
}

export const SPEED_MS: Record<Settings['speed'], number> = { fast: 400, normal: 900, slow: 1600 };

export const ENV_KEY: string = (import.meta.env?.VITE_GEMINI_API_KEY as string | undefined) ?? '';

export const DEFAULT_SETTINGS: Settings = { apiKey: '', model: 'gemini-2.5-flash', speed: 'normal', rememberEngine: false, terminalAutoOpened: false };

function read<T>(key: string): T | undefined {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : undefined;
  } catch {
    return undefined;
  }
}

/** Returns false when storage is full or blocked. */
export function write(key: string, value: unknown): boolean {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function loadSettings(): Settings {
  return { ...DEFAULT_SETTINGS, ...(read<Partial<Settings>>(KEYS.settings) ?? {}) };
}

export function loadSession(): { role: Role } | null {
  const s = read<{ role: Role }>(KEYS.session);
  return s && ['ingest', 'analyst', 'admin'].includes(s.role) ? s : null;
}

export function loadData(): { data?: EngineData; migrated: boolean } {
  const d = read<EngineData>(KEYS.state);
  if (!d) return { migrated: false };
  if (d.version !== 1 || !Array.isArray(d.audit) || !Array.isArray(d.events)) {
    try { localStorage.removeItem(KEYS.state); } catch { /* ignore */ }
    return { migrated: true };
  }
  return { data: d, migrated: false };
}

export function loadChecklist(): boolean[] {
  return read<boolean[]>(KEYS.checklist) ?? [];
}

export function loadEngineOn(): boolean {
  return read<boolean>(KEYS.engine) ?? false;
}

export function storageBytes(): number {
  let total = 0;
  try {
    for (const k of Object.values(KEYS)) total += (localStorage.getItem(k)?.length ?? 0) * 2;
  } catch { /* ignore */ }
  return total;
}

export function clearAll() {
  try {
    for (const k of Object.values(KEYS)) localStorage.removeItem(k);
  } catch { /* ignore */ }
}
