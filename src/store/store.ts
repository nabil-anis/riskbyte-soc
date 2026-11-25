import { create, type UseBoundStore, type StoreApi } from 'zustand';
import type { AgentPolicy, AuditStatus, ClientId, EngineData, LogLevel, LogLine, LogSource, Role } from '../engine/types';
import { classifyLog } from '../engine/types';
import { USERNAMES } from '../engine/auth';
import { Engine, emptyData } from '../engine/engineState';
import { request, type ApiResponse, type Method, type RequestOptions } from '../engine/api';
import { TOKENS, actorFor } from '../engine/auth';
import { RULES } from '../data/rules';
import { INDICATORS } from '../data/indicators';
import { getOrgs } from '../data/clients';
import { ATTACKS, attackById, defaultTarget, generate, type AttackType } from '../engine/generators';
import { baselineBatch } from '../engine/baseline';
import { serverGeminiConfigured } from '../engine/gemini';
import { ENV_KEY, KEYS, clearAll, loadData, loadLogs, loadSettings, loadWorkspace, write, type Settings, type Workspace } from './persist';

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
    { id: 'logs', label: 'Live logs', icon: '☷' },
    { id: 'stream', label: 'Event stream', icon: '≋' },
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
  /** whether the server-side proxy has GEMINI_API_KEY configured */
  serverAi: 'checking' | 'available' | 'unavailable';
  monitor: { lastScanAt: number | null; scans: number; lastRejectAt: number | null };
}

interface Actions {
  enter: (w: Workspace, view?: string) => void;
  leave: () => void;
  go: (view: string, extra?: Partial<State>) => void;
  log: (level: LogLevel, text: string, src?: LogSource) => void;
  /** Records a user action in the live log (who did what, where). */
  track: (action: string, detail?: string) => void;
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
const initialLogs: LogLine[] = typeof localStorage !== 'undefined' ? loadLogs<LogLine>().slice(-800) : [];
logSeq = initialLogs.reduce((m, l) => Math.max(m, l.id), 0);
let logPersistTimer: ReturnType<typeof setTimeout> | null = null;
function scheduleLogPersist() {
  if (logPersistTimer) return;
  logPersistTimer = setTimeout(() => {
    logPersistTimer = null;
    write(KEYS.logs, useStore.getState().logs.slice(-800));
  }, 1500);
}

export function effectiveKey(s: Settings) {
  return s.apiKey || ENV_KEY;
}

export type AiMode = 'browser' | 'server' | 'heuristic';
/** Which AI the agent uses: a key entered in the browser, the server's GEMINI_API_KEY, or the local heuristic. */
export function aiMode(st: { settings: Settings; serverAi: State['serverAi'] }): AiMode {
  if (effectiveKey(st.settings)) return 'browser';
  return st.serverAi === 'available' ? 'server' : 'heuristic';
}
export function aiLabel(st: { settings: Settings; serverAi: State['serverAi'] }): string {
  const m = aiMode(st);
  return m === 'heuristic' ? (st.serverAi === 'checking' ? 'checking…' : 'Heuristic') : `Gemini · ${st.settings.model}`;
}

export interface TierStatus { active: boolean; reason: string }
/** Tiers stay on standby while everything is normal and become active only when something is wrong. */
export function tierStatus(st: Pick<State, 'data' | 'audit' | 'monitor'>, now = Date.now()): Record<'analyst' | 'admin' | 'ingest', TierStatus> {
  const pending = st.data.alerts.filter((a) => a.status === 'new' || a.status === 'triaged').length;
  const critOpen = st.data.cases.filter((c) => c.status === 'open' && c.severity === 'CRITICAL').length;
  const recent = st.data.alerts.filter((a) => now - Date.parse(a.ts) <= 5 * 60_000).length;
  const rejected = !!st.monitor.lastRejectAt && now - st.monitor.lastRejectAt <= 5 * 60_000;
  return {
    analyst: pending ? { active: true, reason: `${pending} alert${pending > 1 ? 's' : ''} awaiting approval` } : { active: false, reason: 'Queue clear · agent handling triage' },
    admin: !st.audit.intact ? { active: true, reason: `Ledger integrity failure at block #${st.audit.brokenAt}` }
      : critOpen ? { active: true, reason: `${critOpen} critical incident${critOpen > 1 ? 's' : ''} open` }
      : { active: false, reason: 'Platform healthy · ledger intact' },
    ingest: rejected ? { active: true, reason: 'Malformed telemetry rejected in the last 5 min' }
      : recent ? { active: true, reason: `Hostile telemetry in stream · ${recent} detection${recent > 1 ? 's' : ''} in 5 min` }
      : { active: false, reason: 'Streaming normally' },
  };
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
  logs: initialLogs,
  settings: initialSettings,
  usingEnvKey: !initialSettings.apiKey && !!ENV_KEY,
  toasts: [],
  selectedAlertId: null,
  selectedCaseId: null,
  launches: [],
  continuous: { on: false, nextAt: null },
  bootedAt: Date.now(),
  serverAi: 'checking',
  monitor: { lastScanAt: null, scans: 0, lastRejectAt: null },

  set: (p) => set(p),

  enter: (w, view) => {
    write(KEYS.session, { workspace: w });
    set({ workspace: w, view: view ?? VIEWS[w][0].id });
    get().track('opened workspace', `${WORKSPACE_LABEL[w]} → ${view ?? VIEWS[w][0].id}`);
    get().log('INFO', `session opened workspace=${w} role=${WORKSPACE_ROLE[w]} token=${TOKENS[WORKSPACE_ROLE[w]]}`);
  },
  leave: () => {
    get().track('left workspace', get().workspace ? WORKSPACE_LABEL[get().workspace!] : '');
    try { localStorage.removeItem(KEYS.session); } catch { /* ignore */ }
    set({ workspace: null, view: '' });
  },
  go: (view, extra) => {
    if (view !== get().view) get().track('navigated', `${get().workspace}/${view}`);
    set({ view, ...(extra ?? {}) });
  },

  log: (level, text, src) => {
    const line: LogLine = { id: ++logSeq, ts: hhmmss(), at: new Date().toISOString(), level, text, src: src ?? classifyLog(text) };
    set((s) => ({ logs: s.logs.length > 3000 ? [...s.logs.slice(-2500), line] : [...s.logs, line] }));
    scheduleLogPersist();
  },
  track: (action, detail) => {
    const ws = get().workspace;
    const actor = ws ? (ws === 'demo' ? 'simulator:operator' : `${WORKSPACE_ROLE[ws]}:${USERNAMES[WORKSPACE_ROLE[ws]]}`) : 'visitor';
    get().log('INFO', `user ${actor} ${action}${detail ? ` · ${detail}` : ''}`, 'user');
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
    if ((res.status === 400 || res.status === 413) && path.startsWith('/api/ingest')) set((s) => ({ monitor: { ...s.monitor, lastRejectAt: Date.now() } }));
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
    const changed = Object.keys(p).filter((k) => k !== 'policy').map((k) => (k === 'apiKey' ? `apiKey=${p.apiKey ? '(set, hidden)' : '(cleared)'}` : `${k}=${String((p as Record<string, unknown>)[k])}`));
    if (changed.length) get().track('updated settings', changed.join(' '));
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
    get().track('launched attack', `${def.label} → ${type === 'ledger_tamper' ? 'audit ledger' : `${org}/${target || defaultTarget(org, type)}`} intensity=${intensity}`);
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
  cancelLaunch: () => {
    if (get().launches.some((l) => l.status === 'running')) get().track('stopped attack');
    launchToken++;
  },

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
    get().track(kind === 'approve' ? 'approved containment' : 'dismissed alert', alertId);
    const res = await get().api('POST', `/api/alerts/${alertId}/${kind}`);
    if (res.status === 200) {
      const b = res.body as { idempotent?: boolean; block?: { index: number } };
      if (b.idempotent) get().toast(`Already ${kind === 'approve' ? 'approved' : 'dismissed'}`);
      else get().toast(kind === 'approve' ? `${alertId} approved · containment executed (dry-run) · audit #${b.block?.index}` : `${alertId} dismissed · audit #${b.block?.index}`, 'ok');
    }
  },

  verifyAudit: async () => {
    get().track('requested ledger verification');
    const st: AuditStatus = await engine.verify();
    get().log(st.intact ? 'OK' : 'ERROR', st.intact ? `verify-audit: intact (${st.blocks} blocks, SHA-256)` : `verify-audit: TAMPERED at block #${st.brokenAt}`);
    return st;
  },
  repair: async () => {
    get().track('rebuilt audit chain');
    await engine.repair(actorFor('admin'));
    get().toast(get().audit.intact ? 'Ledger rebuilt. Hash chain intact.' : 'Repair failed', get().audit.intact ? 'ok' : 'error');
  },
  resetData: async () => {
    get().track('cleared platform data');
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
    get().track('onboarded organization', o.name);
    const org = await engine.addOrg(o, actorFor('admin'));
    get().toast(`${org.name} onboarded (id ${org.id})`, 'ok');
    return true;
  },
  removeOrg: async (id) => {
    get().track('offboarded organization', id);
    const ok = await engine.removeOrg(id, actorFor('admin'));
    get().toast(ok ? 'Organization offboarded. History is kept.' : 'At least one organization is required', ok ? 'ok' : 'error');
  },
  clearAllData: () => {
    get().track('factory reset');
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
      const st = useStore.getState();
      const s: Settings = st.settings;
      return { apiKey: effectiveKey(s), model: s.model || 'gemini-2.5-flash', server: !effectiveKey(s) && st.serverAi === 'available' };
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
    const st = useStore.getState();
    return aiMode(st) !== 'heuristic' ? { provider: 'gemini' as const, model: st.settings.model } : { provider: 'heuristic' as const, model: 'riskbyte-heuristic-v1' };
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

// Log what the user opens (alerts, incidents) as they browse.
let lastSel: { a: string | null; c: string | null } = { a: null, c: null };
export function startActivityTracking() {
  useStore.subscribe((s) => {
    if (s.selectedAlertId !== lastSel.a) {
      lastSel = { ...lastSel, a: s.selectedAlertId };
      if (s.selectedAlertId) s.track('viewed alert', s.selectedAlertId);
    }
    if (s.selectedCaseId !== lastSel.c) {
      lastSel = { ...lastSel, c: s.selectedCaseId };
      if (s.selectedCaseId) s.track('opened incident', s.selectedCaseId);
    }
  });
}

export async function bootstrap() {
  startActivityTracking();
  if (useStore.getState().logs.length) useStore.getState().log('INFO', `riskbyte  restored ${useStore.getState().logs.length} log lines from previous session`);
  try { localStorage.removeItem('riskbyte.state.v1'); localStorage.removeItem('riskbyte.checklist.v1'); localStorage.removeItem('riskbyte.engine.v1'); } catch { /* ignore */ }
  await engine.init();
  const serverOk = await serverGeminiConfigured();
  useStore.setState({ serverAi: serverOk ? 'available' : 'unavailable' });
  const st = useStore.getState();
  const mode = aiMode(st);
  const lines: [LogLevel, string][] = [
    ['INFO', 'riskbyte  agent starting (in-browser engine)'],
    ['INFO', `riskbyte  storage: browser localStorage (key ${KEYS.state})`],
    ['INFO', `riskbyte  organizations: ${engine.data.orgs.map((o) => o.id).join(', ')}`],
    ['INFO', `riskbyte  loaded ${RULES.length} Sigma rules, ${INDICATORS.length} threat-intel indicators`],
    [engine.auditStatus.intact ? 'INFO' : 'WARN', `riskbyte  audit ledger verified: ${engine.auditStatus.blocks} blocks, ${engine.auditStatus.intact ? 'chain intact' : `chain TAMPERED at block #${engine.auditStatus.brokenAt}`}`],
    ['INFO', 'riskbyte  syslog UDP listener 0.0.0.0:5514 (simulated) · REST POST /api/ingest ready'],
    ['INFO', mode === 'server' ? `riskbyte  AI triage provider: gemini (${st.settings.model}) via server key GEMINI_API_KEY`
      : mode === 'browser' ? `riskbyte  AI triage provider: gemini (${st.settings.model}) via browser key`
      : 'riskbyte  AI triage provider: heuristic (no Gemini key on server or in browser)'],
    ['OK', 'riskbyte  agent online. Continuous monitoring started (24/7).'],
  ];
  for (const [l, t] of lines) st.log(l, t);
  startMonitoring();
  if (loaded.migrated) setTimeout(() => useStore.getState().toast('Stored data was from an older version and was reset.'), 300);
}

// ---------------- 24/7 monitoring ----------------
let monitorTimer: ReturnType<typeof setTimeout> | null = null;
let checkpointEvents = 0;
let checkpointAlerts = 0;
const CHECKPOINT_MS = 5 * 60_000;

/** Continuous baseline telemetry from every organization, scanned by the detection engine nonstop. */
export function startMonitoring() {
  if (monitorTimer) return;
  let lastCheckpoint = Date.now();
  const tick = async () => {
    const orgs = getOrgs();
    const batch = baselineBatch(orgs);
    if (batch.length) {
      const before = engine.data.alerts.length;
      const res = await request(apiCtx, 'POST', '/api/ingest', { token: TOKENS.ingest, body: { events: batch }, origin: 'ingest-api', silent: true, quiet: true, auditMode: 'onAlert' });
      if (res.status === 200) {
        checkpointEvents += batch.length;
        checkpointAlerts += engine.data.alerts.length - before;
        useStore.setState((s) => ({ monitor: { ...s.monitor, lastScanAt: Date.now(), scans: s.monitor.scans + 1 } }));
      }
    }
    if (Date.now() - lastCheckpoint >= CHECKPOINT_MS) {
      lastCheckpoint = Date.now();
      const inWindow = engine.data.alerts.filter((a) => Date.now() - Date.parse(a.ts) <= CHECKPOINT_MS).length;
      await engine.checkpoint(`Monitoring checkpoint: ${checkpointEvents} baseline events scanned across ${orgs.length} organizations in the last 5 min; ${inWindow} detection(s) in window`);
      checkpointEvents = 0;
      checkpointAlerts = 0;
    }
    monitorTimer = setTimeout(tick, 2500 + Math.round(Math.random() * 1500));
  };
  monitorTimer = setTimeout(tick, 800);
}
