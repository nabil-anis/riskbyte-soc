import { create, type UseBoundStore, type StoreApi } from 'zustand';
import type { AuditStatus, EngineData, LogLevel, LogLine, Role, ClientId } from '../engine/types';
import { Engine, emptyData } from '../engine/engineState';
import { request, type ApiResponse, type Method, type RequestOptions } from '../engine/api';
import { TOKENS, actorFor } from '../engine/auth';
import { RULES } from '../data/rules';
import { INDICATORS } from '../data/indicators';
import { SCENARIOS, scenarioById, scenarioEvents } from '../data/scenarios';
import { generate, type AttackType } from '../engine/generators';
import {
  ENV_KEY, KEYS, clearAll, loadChecklist, loadData, loadEngineOn, loadSession, loadSettings, write, type Settings,
} from './persist';

export type Tab = 'alerts' | 'cases' | 'demo' | 'admin' | 'audit' | 'license' | 'ingest';
export const TABS: { id: Tab; label: string }[] = [
  { id: 'alerts', label: 'Alerts' },
  { id: 'cases', label: 'Cases' },
  { id: 'demo', label: 'Demo' },
  { id: 'admin', label: 'Admin Overview' },
  { id: 'audit', label: 'Audit Trail' },
  { id: 'license', label: 'License & Health' },
  { id: 'ingest', label: 'Telemetry Ingest' },
];
export const DEFAULT_TAB: Record<Role, Tab> = { analyst: 'alerts', admin: 'admin', ingest: 'ingest' };
export const ROLE_LABEL: Record<Role, string> = { analyst: 'Security Analyst', admin: 'Administrator', ingest: 'Telemetry Ingest' };

export function canView(role: Role, tab: Tab) {
  return role === 'ingest' ? tab === 'ingest' || tab === 'license' : true;
}

export interface Toast { id: number; text: string; tone?: 'info' | 'error' | 'ok' }

export interface DemoRun {
  runId: number;
  scenarioId: string;
  startedAt: number;
  eventCountBefore: number;
  alertCountBefore: number;
  status: 'running' | 'done' | 'error';
  accepted?: number;
  processingMs?: number;
  alertId?: string;
  dedupedFrom?: string;
  error?: string;
}

export interface Playground {
  running: boolean;
  sent: number;
  total: number;
  label: string;
}

interface State {
  session: { role: Role } | null;
  tab: Tab;
  engineOn: boolean;
  booting: boolean;
  data: EngineData;
  audit: AuditStatus;
  logs: LogLine[];
  terminalOpen: boolean;
  paused: boolean;
  settings: Settings;
  usingEnvKey: boolean;
  island: { kind: 'switched' | 'critical'; until: number; text?: string } | null;
  toasts: Toast[];
  settingsOpen: boolean;
  guideOpen: boolean;
  checklist: boolean[];
  selectedAlertId: string | null;
  selectedCaseId: string | null;
  demoRun: DemoRun | null;
  demoClient: ClientId;
  playground: Playground;
  autoAttack: { on: boolean; nextAt: number | null };
}

interface Actions {
  login: (role: Role) => void;
  switchRole: (role: Role) => void;
  signOut: () => void;
  setTab: (tab: Tab) => void;
  setEngine: (on: boolean) => Promise<void>;
  log: (level: LogLevel, text: string) => void;
  clearLogs: () => void;
  toast: (text: string, tone?: Toast['tone']) => void;
  dismissToast: (id: number) => void;
  api: (method: Method, path: string, opts?: Omit<RequestOptions, 'token'> & { quiet403?: boolean }) => Promise<ApiResponse>;
  updateSettings: (p: Partial<Settings>) => void;
  runScenario: (id: string) => Promise<void>;
  launchPlayground: (type: AttackType, client: ClientId, target: string, intensity: number, label: string) => Promise<void>;
  cancelPlayground: () => void;
  setAutoAttack: (on: boolean) => void;
  decide: (alertId: string, kind: 'approve' | 'dismiss') => Promise<void>;
  verifyAudit: () => Promise<AuditStatus>;
  tamper: () => Promise<void>;
  repair: () => Promise<void>;
  resetDemo: () => Promise<void>;
  clearAllData: () => void;
  toggleCheck: (i: number) => void;
  set: (p: Partial<State>) => void;
}

export type Store = State & Actions;

let logSeq = 0;
let toastSeq = 0;
let runSeq = 0;
let playgroundToken = 0;
let autoTimer: ReturnType<typeof setTimeout> | null = null;
let persistTimer: ReturnType<typeof setTimeout> | null = null;
let quotaWarned = false;

const hhmmss = () => new Date().toTimeString().slice(0, 8);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const initialSettings = loadSettings();
const usingEnvKey = !initialSettings.apiKey && !!ENV_KEY;
const loaded = typeof localStorage !== 'undefined' ? loadData() : { migrated: false };
const session = loadSession();

export function effectiveKey(s: Settings) {
  return s.apiKey || ENV_KEY;
}

export const useStore: UseBoundStore<StoreApi<Store>> = create<Store>()((set, get) => ({
  session,
  tab: session ? DEFAULT_TAB[session.role] : 'alerts',
  engineOn: false,
  booting: false,
  data: loaded.data ?? emptyData(),
  audit: { intact: true, blocks: loaded.data?.audit.length ?? 0, checkedAt: new Date().toISOString() },
  logs: [],
  terminalOpen: false,
  paused: false,
  settings: initialSettings,
  usingEnvKey,
  island: null,
  toasts: [],
  settingsOpen: false,
  guideOpen: false,
  checklist: loadChecklist(),
  selectedAlertId: null,
  selectedCaseId: null,
  demoRun: null,
  demoClient: 'meezan',
  playground: { running: false, sent: 0, total: 0, label: '' },
  autoAttack: { on: false, nextAt: null },

  set: (p) => set(p),

  login: (role) => {
    write(KEYS.session, { role });
    set({ session: { role }, tab: DEFAULT_TAB[role] });
    get().log('INFO', `session created role=${role} token=${TOKENS[role]}`);
  },
  switchRole: (role) => {
    write(KEYS.session, { role });
    const { tab } = get();
    set({ session: { role }, tab: canView(role, tab) ? tab : DEFAULT_TAB[role], island: { kind: 'switched', until: Date.now() + 3000, text: `Switched to ${ROLE_LABEL[role]}` } });
    get().log('INFO', `role switched to ${role} (token ${TOKENS[role]})`);
    get().toast(`You are now the ${ROLE_LABEL[role]}`);
  },
  signOut: () => {
    try { localStorage.removeItem(KEYS.session); } catch { /* ignore */ }
    get().cancelPlayground();
    get().setAutoAttack(false);
    set({ session: null, guideOpen: false, settingsOpen: false });
  },
  setTab: (tab) => set({ tab }),

  log: (level, text) => {
    const line: LogLine = { id: ++logSeq, ts: hhmmss(), level, text };
    set((s) => ({ logs: s.logs.length > 1500 ? [...s.logs.slice(-1200), line] : [...s.logs, line] }));
  },
  clearLogs: () => set({ logs: [] }),

  toast: (text, tone = 'info') => {
    const id = ++toastSeq;
    set((s) => ({ toasts: [...s.toasts.slice(-2), { id, text, tone }] }));
    setTimeout(() => get().dismissToast(id), 4000);
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  setEngine: async (on) => {
    const s = get();
    if (s.booting || s.engineOn === on) return;
    if (on) {
      set({ booting: true });
      if (!s.settings.terminalAutoOpened) {
        set({ terminalOpen: true });
        get().updateSettings({ terminalAutoOpened: true });
      }
      const status = await engine.verify();
      const key = effectiveKey(get().settings);
      const lines: [LogLevel, string][] = [
        ['INFO', 'Riskbyte starting (in-browser engine, dev mode)'],
        ['INFO', `Storage: browser localStorage (key ${KEYS.state})`],
        ['INFO', `Loaded ${RULES.length} Sigma rules`],
        ['INFO', `Threat intel loaded: ${INDICATORS.length} indicators`],
        [status.intact ? 'INFO' : 'WARN', `Audit ledger verified: ${status.blocks} blocks, ${status.intact ? 'chain intact' : `chain TAMPERED at block #${status.brokenAt}`}`],
        ['INFO', 'Syslog UDP listener on 0.0.0.0:5514 (simulated)'],
        ['INFO', 'REST ingest ready: POST /api/ingest (in-browser)'],
        ['INFO', key ? `AI triage provider: gemini (model ${get().settings.model})` : 'AI triage provider: heuristic (no API key set)'],
        ['OK', 'Engine ready. Listening for telemetry.'],
      ];
      for (const [lvl, text] of lines) {
        get().log(lvl, `riskbyte  ${text}`);
        await sleep(120 + Math.round(Math.random() * 130));
      }
      set({ booting: false, engineOn: true });
      write(KEYS.engine, true);
    } else {
      get().log('INFO', 'riskbyte  Engine shutting down');
      get().cancelPlayground();
      get().setAutoAttack(false);
      await sleep(150);
      set({ engineOn: false });
      get().log('INFO', 'riskbyte  Engine stopped');
      write(KEYS.engine, false);
    }
  },

  api: async (method, path, opts = {}) => {
    const role = get().session?.role;
    const res = await request(apiCtx, method, path, { ...opts, token: role ? TOKENS[role] : undefined });
    if (res.status >= 400) {
      const b = res.body as { error?: string; detail?: string; problems?: string[]; route?: string; suggestion?: string };
      const msg =
        res.status === 403 ? `403 Forbidden: ${b.detail}. Switch role from the badge in the top bar.`
        : res.status === 401 ? '401: You are not signed in. Pick a role on the login screen.'
        : res.status === 404 ? `404: ${b.route ?? path} not found. ${b.suggestion ?? ''}`
        : res.status === 409 ? `409: ${b.detail}`
        : res.status === 413 ? `413: ${b.detail}`
        : res.status === 400 ? `400: ${b.problems?.[0] ?? 'Invalid request'}`
        : res.status === 503 ? `${b.detail}.`
        : `${res.status}: ${b.detail ?? b.error ?? 'Request failed'}`;
      get().toast(`${method} ${path.split('?')[0]} → ${msg}`, 'error');
    }
    return res;
  },

  updateSettings: (p) => {
    const settings = { ...get().settings, ...p };
    write(KEYS.settings, settings);
    set({ settings, usingEnvKey: !settings.apiKey && !!ENV_KEY });
  },

  runScenario: async (id) => {
    const s = scenarioById(id);
    if (!s || !get().engineOn) return;
    const cur = get().demoRun;
    if (cur?.status === 'running' || get().playground.running) return;
    const run: DemoRun = {
      runId: ++runSeq, scenarioId: id, startedAt: Date.now(), status: 'running',
      eventCountBefore: get().data.counters.event, alertCountBefore: get().data.counters.alert,
    };
    set({ demoRun: run });
    get().log('ALERT', `attack launched: ${s.title} (${s.client}) — simulated`);
    const res = await get().api('POST', '/api/ingest', { body: { events: scenarioEvents(s) }, origin: 'demo', scenarioId: id });
    if (get().demoRun?.runId !== run.runId) return;
    if (res.status !== 200) {
      set({ demoRun: { ...run, status: 'error', error: (res.body as { detail?: string }).detail ?? 'Ingest failed' } });
      return;
    }
    const out = res.body as { accepted: number; processingMs: number; alertIds: string[]; deduped: { alertId: string; ruleId: string }[] };
    const alertId = out.alertIds.find((aid) => get().data.alerts.find((a) => a.id === aid)?.ruleId === s.ruleId) ?? out.alertIds[0];
    const dedup = out.deduped.find((d) => d.ruleId === s.ruleId);
    set({ demoRun: { ...run, status: 'done', accepted: out.accepted, processingMs: out.processingMs, alertId: alertId ?? dedup?.alertId, dedupedFrom: !alertId ? dedup?.alertId : undefined } });
  },

  launchPlayground: async (type, client, target, intensity, label) => {
    if (!get().engineOn || get().playground.running) return;
    const token = ++playgroundToken;
    const evs = generate(type, client, target, intensity);
    set({ playground: { running: true, sent: 0, total: evs.length, label } });
    get().log('ALERT', `playground launch: ${label} client=${client} target=${target} intensity=${intensity} events=${evs.length}`);
    for (let i = 0; i < evs.length; i++) {
      const { delayMs, ...e } = evs[i];
      if (delayMs) await sleep(delayMs);
      if (token !== playgroundToken || !get().engineOn) {
        get().log('WARN', `playground run cancelled after ${i}/${evs.length} events`);
        set({ playground: { running: false, sent: i, total: evs.length, label } });
        return;
      }
      // keep each event's timestamp at "now" so live streaming feels real
      await get().api('POST', '/api/ingest', { body: { events: [{ ...e, ts: new Date().toISOString() }] }, origin: 'playground' });
      set((st) => ({ playground: { ...st.playground, sent: i + 1 } }));
    }
    set((st) => ({ playground: { ...st.playground, running: false } }));
    get().toast(`Playground finished: ${evs.length} events sent`, 'ok');
  },
  cancelPlayground: () => {
    playgroundToken++;
    set((s) => ({ playground: { ...s.playground, running: false } }));
  },

  setAutoAttack: (on) => {
    if (autoTimer) clearTimeout(autoTimer);
    autoTimer = null;
    if (!on || !get().engineOn) {
      if (get().autoAttack.on) get().log('INFO', 'auto-attack stopped');
      set({ autoAttack: { on: false, nextAt: null } });
      return;
    }
    const schedule = () => {
      const delay = 20000 + Math.round(Math.random() * 10000);
      set({ autoAttack: { on: true, nextAt: Date.now() + delay } });
      autoTimer = setTimeout(async () => {
        if (!get().engineOn || !get().autoAttack.on) return get().setAutoAttack(false);
        const s = SCENARIOS[Math.floor(Math.random() * SCENARIOS.length)];
        get().log('ALERT', `auto-attack fired: ${s.title} (${s.client}) — simulated`);
        get().toast(`Auto-attack: ${s.title}`);
        await get().api('POST', '/api/ingest', { body: { events: scenarioEvents(s) }, origin: 'demo', scenarioId: s.id });
        if (get().autoAttack.on && get().engineOn) schedule();
      }, delay);
    };
    get().log('INFO', 'auto-attack enabled (random scenario every 20-30s; never auto-approves)');
    schedule();
  },

  decide: async (alertId, kind) => {
    const res = await get().api('POST', `/api/alerts/${alertId}/${kind}`);
    if (res.status === 200) {
      const b = res.body as { idempotent?: boolean; block?: { index: number } };
      if (b.idempotent) get().toast(`Already ${kind === 'approve' ? 'approved' : 'dismissed'}; showing the existing outcome`);
      else get().toast(kind === 'approve' ? `Approved. Dry-run executed and written to audit block #${b.block?.index}` : `Alert dismissed (audit block #${b.block?.index})`, 'ok');
    }
  },

  verifyAudit: async () => {
    const st: AuditStatus = await engine.verify();
    get().log(st.intact ? 'OK' : 'ERROR', st.intact ? `verify-audit: Intact (${st.blocks} blocks, SHA-256)` : `verify-audit: TAMPERED at block #${st.brokenAt}`);
    return st;
  },
  tamper: async () => {
    const role = get().session?.role;
    if (role !== 'admin') return get().toast('Only the Administrator can run the tamper demo', 'error');
    await engine.tamper();
    const st = get().audit;
    if (!st.intact) get().toast(`Tampering detected at block #${st.brokenAt}`, 'error');
  },
  repair: async () => {
    if (get().session?.role !== 'admin') return get().toast('Only the Administrator can repair the ledger', 'error');
    await engine.repair(actorFor('admin'));
    get().toast(get().audit.intact ? 'Chain rebuilt. Hash Chain: Intact' : 'Repair failed', get().audit.intact ? 'ok' : 'error');
  },
  resetDemo: async () => {
    get().cancelPlayground();
    get().setAutoAttack(false);
    const res = await get().api('POST', '/api/demo/reset');
    if (res.status === 200) {
      set({ demoRun: null, selectedAlertId: null, selectedCaseId: null });
      get().toast('Demo data reset. Fresh ledger started.', 'ok');
    }
  },
  clearAllData: () => {
    clearAll();
    window.location.hash = '';
    window.location.reload();
  },
  toggleCheck: (i) => {
    const c = [...get().checklist];
    c[i] = !c[i];
    write(KEYS.checklist, c);
    set({ checklist: c });
  },
}));

// ---------------- Engine wiring ----------------
const engine: Engine = new Engine(
  {
    log: (level, text) => useStore.getState().log(level, text),
    triageConfig: () => {
      const s: Settings = useStore.getState().settings;
      return { apiKey: effectiveKey(s), model: s.model || 'gemini-2.5-flash' };
    },
    onChange: (data, audit) => {
      const prev = useStore.getState().data;
      const prevIds = new Set(prev.alerts.map((a) => a.id));
      const newCritical = data.alerts.find((a) => !prevIds.has(a.id) && a.severity === 'CRITICAL');
      useStore.setState({ data, audit, ...(newCritical ? { island: { kind: 'critical' as const, until: Date.now() + 6000 } } : {}) });
      if (persistTimer) clearTimeout(persistTimer);
      persistTimer = setTimeout(() => {
        const ok = write(KEYS.state, useStore.getState().data);
        if (!ok && !quotaWarned) {
          quotaWarned = true;
          useStore.getState().toast('Browser storage is full; recent data is kept in memory only.', 'error');
        }
      }, 400);
    },
  },
  loaded.data,
);

export const apiCtx = {
  engine,
  isEngineOn: () => useStore.getState().engineOn,
  provider: () => {
    const s = useStore.getState().settings;
    return effectiveKey(s) ? { provider: 'gemini' as const, model: s.model } : { provider: 'heuristic' as const, model: 'riskbyte-heuristic-v1' };
  },
  log: (level: LogLevel, text: string) => useStore.getState().log(level, text),
};

export { engine };

export async function bootstrap() {
  await engine.init();
  if (loaded.migrated) setTimeout(() => useStore.getState().toast('Stored data was from an older version and was reset.'), 300);
  const s = useStore.getState().settings;
  if (s.rememberEngine && loadEngineOn()) await useStore.getState().setEngine(true);
}
