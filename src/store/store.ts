import { create, type UseBoundStore, type StoreApi } from 'zustand';
import type { AgentPolicy, AuditStatus, ClientId, EngineData, LogLevel, LogLine, Role } from '../engine/types';
import { Engine, emptyData } from '../engine/engineState';
import { request, type ApiResponse, type Method, type RequestOptions } from '../engine/api';
import { TOKENS, actorFor } from '../engine/auth';
import { RULES } from '../data/rules';
import { INDICATORS } from '../data/indicators';
import { getOrgs } from '../data/clients';
import { ATTACKS, attackById, defaultTarget, generate, type AttackType } from '../engine/generators';
import { ENV_KEY, KEYS, clearAll, loadData, loadSettings, loadWorkspace, write, type Settings, type Workspace } from './persist';

export type { Workspace };

export const VIEWS: Record<Workspace, { id: string; label: string; icon: string }[]> = {
  analyst: [
    { id: 'overview', label: 'Overview', icon: '◎' },
    { id: 'alerts', label: 'Alert queue', icon: '⚑' },
    { id: 'incidents', label: 'Incidents', icon: '▣' },
    { id: 'activity', label: 'Agent activity', icon: '≋' },
  ],
  admin: [
    { id: 'overview', label: 'Overview', icon: '◎' },
    { id: 'orgs', label: 'Organizations', icon: '▦' },
    { id: 'agent', label: 'AI agent & policy', icon: '✦' },
    { id: 'rules', label: 'Detection rules', icon: '☰' },
    { id: 'intel', label: 'Threat intel', icon: '⊘' },
    { id: 'ledger', label: 'Audit ledger', icon: '⛓' },
    { id: 'system', label: 'System', icon: '⚙' },
  ],
  ingest: [
    { id: 'overview', label: 'Sources', icon: '◎' },
    { id: 'stream', label: 'Live stream', icon: '≋' },
    { id: 'send', label: 'Send events', icon: '⇪' },
    { id: 'console', label: 'Pipeline console', icon: '>_' },
  ],
  demo: [{ id: 'attacks', label: 'Attack simulator', icon: '⚡' }],
};

export const WORKSPACE_LABEL: Record<Workspace, string> = {
  analyst: 'Security Analyst',
  admin: 'Administrator',
  ingest: 'Telemetry Ingestion',
  demo: 'Attack Simulator',
};

/** API role each workspace authenticates as. The simulator sends telemetry like any log shipper. */
export const WORKSPACE_ROLE: Record<Workspace, Role> = { analyst: 'analyst', admin: 'admin', ingest: 'ingest', demo: 'ingest' };

export interface Toast { id: number; text: string; tone?: 'info' | 'error' | 'ok' }

export interface Launch {
  id: number;
  attack: AttackType;
  org: ClientId;
  target: string;
  startedAt: number;
  sent: number;
  total: number;
  status: 'running' | 'delivered' | 'cancelled' | 'failed';
  firstEventNum: number;
  detail?: string;
}

interface State {
  workspace: Workspace | null;
  view: string;
  data: EngineData;
  audit: AuditStatus;
  logs: LogLine[];
  settings: Settings;
  usingEnvKey: boolean;
  toasts: Toast[];
  selectedAlertId: string | null;
  selectedCaseId: string | null;
  launches: Launch[];
  continuous: { on: boolean; nextAt: number | null };
  bootedAt: number;
}

interface Actions {
  enter: (w: Workspace, view?: string) => void;
  leave: () => void;
  go: (view: string, extra?: Partial<State>) => void;
  log: (level: LogLevel, text: string) => void;
  clearLogs: () => void;
  toast: (text: string, tone?: Toast['tone']) => void;
  dismissToast: (id: number) => void;
  api: (method: Method, path: string, opts?: Omit<RequestOptions, 'token'>) => Promise<ApiResponse>;
  updateSettings: (p: Partial<Settings>) => void;
  setPolicy: (p: Partial<AgentPolicy>) => void;
  launchAttack: (type: AttackType, org: ClientId, target: string, intensity: number) => Promise<void>;
  cancelLaunch: () => void;
  setContinuous: (on: boolean) => void;
  decide: (alertId: string, kind: 'approve' | 'dismiss') => Promise<void>;
  verifyAudit: () => Promise<AuditStatus>;
  repair: () => Promise<void>;
  resetData: () => Promise<void>;
  addOrg: (o: { name: string; sector: string; description?: string }) => Promise<boolean>;
  removeOrg: (id: string) => Promise<void>;
  clearAllData: () => void;
  set: (p: Partial<State>) => void;
}

export type Store = State & Actions;

let logSeq = 0;
let toastSeq = 0;
let launchSeq = 0;
let launchToken = 0;
let contTimer: ReturnType<typeof setTimeout> | null = null;
let persistTimer: ReturnType<typeof setTimeout> | null = null;
let quotaWarned = false;

const hhmmss = () => new Date().toTimeString().slice(0, 8);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const initialSettings = loadSettings();
const loaded = typeof localStorage !== 'undefined' ? loadData() : { migrated: false };
const initialWs = loadWorkspace();

export function effectiveKey(s: Settings) {
  return s.apiKey || ENV_KEY;
}

function parseHash(): { ws: Workspace | null; view: string | null } {
  const [ws, view] = window.location.hash.replace(/^#\/?/, '').split('/');
  if (ws && ws in VIEWS) return { ws: ws as Workspace, view: VIEWS[ws as Workspace].some((v) => v.id === view) ? view : null };
  return { ws: null, view: null };
}

export const useStore: UseBoundStore<StoreApi<Store>> = create<Store>()((set, get) => ({
  workspace: initialWs,
  view: initialWs ? VIEWS[initialWs][0].id : '',
  data: loaded.data ?? emptyData(),
  audit: { intact: true, blocks: loaded.data?.audit.length ?? 0, checkedAt: new Date().toISOString() },
  logs: [],
  settings: initialSettings,
  usingEnvKey: !initialSettings.apiKey && !!ENV_KEY,
  toasts: [],
  selectedAlertId: null,
  selectedCaseId: null,
  launches: [],
  continuous: { on: false, nextAt: null },
  bootedAt: Date.now(),

  set: (p) => set(p),

  enter: (w, view) => {
    write(KEYS.session, { workspace: w });
    set({ workspace: w, view: view ?? VIEWS[w][0].id });
    get().log('INFO', `session opened workspace=${w} role=${WORKSPACE_ROLE[w]} token=${TOKENS[WORKSPACE_ROLE[w]]}`);
  },
  leave: () => {
    try { localStorage.removeItem(KEYS.session); } catch { /* ignore */ }
    set({ workspace: null, view: '' });
  },
  go: (view, extra) => set({ view, ...(extra ?? {}) }),

  log: (level, text) => {
    const line: LogLine = { id: ++logSeq, ts: hhmmss(), level, text };
    set((s) => ({ logs: s.logs.length > 1500 ? [...s.logs.slice(-1200), line] : [...s.logs, line] }));
  },
  clearLogs: () => set({ logs: [] }),

  toast: (text, tone = 'info') => {
    const id = ++toastSeq;
    set((s) => ({ toasts: [...s.toasts.slice(-2), { id, text, tone }] }));
    setTimeout(() => get().dismissToast(id), 4500);
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  api: async (method, path, opts = {}) => {
    const ws = get().workspace;
    const res = await request(apiCtx, method, path, { ...opts, token: ws ? TOKENS[WORKSPACE_ROLE[ws]] : undefined });
    if (res.status >= 400) {
      const b = res.body as { error?: string; detail?: string; problems?: string[]; route?: string; suggestion?: string };
      const msg =
        res.status === 403 ? `403 Forbidden: ${b.detail}.`
        : res.status === 401 ? '401: Not signed in.'
        : res.status === 404 ? `404: ${b.route ?? path} not found. ${b.suggestion ?? ''}`
        : res.status === 409 ? `409: ${b.detail}`
        : res.status === 413 ? `413: ${b.detail}`
        : res.status === 400 ? `400: ${b.problems?.[0] ?? 'Invalid request'}`
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
  setPolicy: (p) => {
    const policy = { ...get().settings.policy, ...p, modes: { ...get().settings.policy.modes, ...(p.modes ?? {}) } };
    get().updateSettings({ policy });
    get().log('INFO', `agent policy updated: ${Object.entries(policy.modes).map(([a, m]) => `${a}=${m}`).join(' ')} min_confidence=${policy.minConfidence}`);
  },

  launchAttack: async (type, org, target, intensity) => {
    if (get().launches.some((l) => l.status === 'running')) return;
    const def = attackById(type);
    const id = ++launchSeq;
    const token = ++launchToken;
    const base: Launch = { id, attack: type, org, target: target || defaultTarget(org, type), startedAt: Date.now(), sent: 0, total: 0, status: 'running', firstEventNum: get().data.counters.event + 1 };

    if (type === 'ledger_tamper') {
      set((s) => ({ launches: [{ ...base, total: 1, target: 'audit ledger' }, ...s.launches].slice(0, 20) }));
      await sleep(600);
      const idx = await engine.tamper();
      set((s) => ({ launches: s.launches.map((l) => (l.id === id ? { ...l, sent: 1, status: idx >= 0 ? 'delivered' : 'failed', detail: idx >= 0 ? `Record #${idx} altered in storage` : 'Ledger empty' } : l)) }));
      return;
    }

    const evs = generate(type, org, target, intensity);
    set((s) => ({ launches: [{ ...base, total: evs.length }, ...s.launches].slice(0, 20) }));
    get().log('ALERT', `simulator: ${def.label} → org=${org} target=${base.target} intensity=${intensity} events=${evs.length}`);
    for (let i = 0; i < evs.length; i++) {
      const { delayMs, ...e } = evs[i];
      if (delayMs) await sleep(delayMs);
      if (token !== launchToken) {
        set((s) => ({ launches: s.launches.map((l) => (l.id === id ? { ...l, status: 'cancelled' } : l)) }));
        return;
      }
      const res = await get().api('POST', '/api/ingest', { body: { events: [{ ...e, ts: new Date().toISOString() }] }, origin: 'demo' });
      if (res.status !== 200) {
        set((s) => ({ launches: s.launches.map((l) => (l.id === id ? { ...l, status: 'failed', detail: (res.body as { detail?: string }).detail } : l)) }));
        return;
      }
      set((s) => ({ launches: s.launches.map((l) => (l.id === id ? { ...l, sent: i + 1 } : l)) }));
    }
    set((s) => ({ launches: s.launches.map((l) => (l.id === id ? { ...l, status: 'delivered' } : l)) }));
  },
  cancelLaunch: () => { launchToken++; },

  setContinuous: (on) => {
    if (contTimer) clearTimeout(contTimer);
    contTimer = null;
    if (!on) {
      if (get().continuous.on) get().log('INFO', 'simulator: continuous attacks stopped');
      set({ continuous: { on: false, nextAt: null } });
      return;
    }
    const pool = ATTACKS.filter((a) => a.ruleId);
    const schedule = () => {
      const delay = 20000 + Math.round(Math.random() * 10000);
      set({ continuous: { on: true, nextAt: Date.now() + delay } });
      contTimer = setTimeout(async () => {
        if (!get().continuous.on) return;
        const a = pool[Math.floor(Math.random() * pool.length)];
        const orgs = getOrgs();
        const o = orgs[Math.floor(Math.random() * orgs.length)];
        if (!get().launches.some((l) => l.status === 'running')) await get().launchAttack(a.id, o.id, '', 3);
        if (get().continuous.on) schedule();
      }, delay);
    };
    get().log('INFO', 'simulator: continuous attacks enabled (random attack every 20-30s)');
    schedule();
  },

  decide: async (alertId, kind) => {
    const res = await get().api('POST', `/api/alerts/${alertId}/${kind}`);
    if (res.status === 200) {
      const b = res.body as { idempotent?: boolean; block?: { index: number } };
      if (b.idempotent) get().toast(`Already ${kind === 'approve' ? 'approved' : 'dismissed'}`);
      else get().toast(kind === 'approve' ? `${alertId} approved · containment executed (dry-run) · audit #${b.block?.index}` : `${alertId} dismissed · audit #${b.block?.index}`, 'ok');
    }
  },

  verifyAudit: async () => {
    const st: AuditStatus = await engine.verify();
    get().log(st.intact ? 'OK' : 'ERROR', st.intact ? `verify-audit: intact (${st.blocks} blocks, SHA-256)` : `verify-audit: TAMPERED at block #${st.brokenAt}`);
    return st;
  },
  repair: async () => {
    await engine.repair(actorFor('admin'));
    get().toast(get().audit.intact ? 'Ledger rebuilt. Hash chain intact.' : 'Repair failed', get().audit.intact ? 'ok' : 'error');
  },
  resetData: async () => {
    get().cancelLaunch();
    get().setContinuous(false);
    const res = await get().api('POST', '/api/demo/reset');
    if (res.status === 200) {
      set({ selectedAlertId: null, selectedCaseId: null, launches: [] });
      get().toast('Platform data cleared. New ledger started.', 'ok');
    }
  },
  addOrg: async (o) => {
    if (!o.name.trim()) return false;
    const org = await engine.addOrg(o, actorFor('admin'));
    get().toast(`${org.name} onboarded (id ${org.id})`, 'ok');
    return true;
  },
  removeOrg: async (id) => {
    const ok = await engine.removeOrg(id, actorFor('admin'));
    get().toast(ok ? 'Organization offboarded. History is kept.' : 'At least one organization is required', ok ? 'ok' : 'error');
  },
  clearAllData: () => {
    clearAll();
    window.location.hash = '';
    window.location.reload();
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
    policy: () => useStore.getState().settings.policy,
    onChange: (data, audit) => {
      const prevAudit = useStore.getState().audit;
      useStore.setState({ data, audit });
      if (prevAudit.intact && !audit.intact) useStore.getState().toast(`Ledger integrity failure at block #${audit.brokenAt}`, 'error');
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
  isEngineOn: () => true,
  provider: () => {
    const s = useStore.getState().settings;
    return effectiveKey(s) ? { provider: 'gemini' as const, model: s.model } : { provider: 'heuristic' as const, model: 'riskbyte-heuristic-v1' };
  },
  log: (level: LogLevel, text: string) => useStore.getState().log(level, text),
};

export { engine };

export function syncFromHash() {
  const { ws, view } = parseHash();
  const st = useStore.getState();
  if (ws && (ws !== st.workspace || (view && view !== st.view))) {
    write(KEYS.session, { workspace: ws });
    useStore.setState({ workspace: ws, view: view ?? VIEWS[ws][0].id });
  } else if (!ws && window.location.hash === '' && st.workspace) {
    // keep the stored session
  }
}

export async function bootstrap() {
  try { localStorage.removeItem('riskbyte.state.v1'); localStorage.removeItem('riskbyte.checklist.v1'); localStorage.removeItem('riskbyte.engine.v1'); } catch { /* ignore */ }
  await engine.init();
  const st = useStore.getState();
  const key = effectiveKey(st.settings);
  const lines: [LogLevel, string][] = [
    ['INFO', 'riskbyte  agent starting (in-browser engine)'],
    ['INFO', `riskbyte  storage: browser localStorage (key ${KEYS.state})`],
    ['INFO', `riskbyte  organizations: ${engine.data.orgs.map((o) => o.id).join(', ')}`],
    ['INFO', `riskbyte  loaded ${RULES.length} Sigma rules, ${INDICATORS.length} threat-intel indicators`],
    [engine.auditStatus.intact ? 'INFO' : 'WARN', `riskbyte  audit ledger verified: ${engine.auditStatus.blocks} blocks, ${engine.auditStatus.intact ? 'chain intact' : `chain TAMPERED at block #${engine.auditStatus.brokenAt}`}`],
    ['INFO', 'riskbyte  syslog UDP listener 0.0.0.0:5514 (simulated) · REST POST /api/ingest ready'],
    ['INFO', key ? `riskbyte  AI triage provider: gemini (${st.settings.model})` : 'riskbyte  AI triage provider: heuristic (no API key set)'],
    ['OK', 'riskbyte  agent online. Listening for telemetry.'],
  ];
  for (const [l, t] of lines) st.log(l, t);
  if (loaded.migrated) setTimeout(() => useStore.getState().toast('Stored data was from an older version and was reset.'), 300);
}
