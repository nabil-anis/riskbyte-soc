import { create, type UseBoundStore, type StoreApi } from 'zustand';
import type { AgentPolicy, AuditStatus, ClientId, EngineData, LogLevel, LogLine, LogSource, Role } from '../engine/types';
import { classifyLog } from '../engine/types';
import { USERNAMES } from '../engine/auth';
import { Engine, emptyData } from '../engine/engineState';
import { request, type ApiResponse, type Method, type RequestOptions } from '../engine/api';
import { TOKENS } from '../engine/auth';
import { RULES } from '../data/rules';
import { INDICATORS } from '../data/indicators';
import { getOrgs } from '../data/clients';
import { ATTACKS, attackById, defaultTarget, generate, type AttackType } from '../engine/generators';
import { baselineBatch } from '../engine/baseline';
import { serverGeminiConfigured } from '../engine/gemini';
import { setLiveIntel } from '../engine/intel';
import type { Indicator } from '../engine/types';
import { MAX_FAILED, LOCK_MS, hashPassword, loadAccounts, loadSessions, newSession, passwordProblem, saveAccounts, saveSessions, verifyPassword, type Account, type Session } from '../engine/accounts';
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
    { id: 'containment', label: 'Containment', icon: '⛨' },
    { id: 'access', label: 'Access', icon: '⚿' },
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
  monitor: { lastScanAt: number | null; scans: number; lastRejectAt: number | null; since: string; lastGap: { from: string; to: string } | null };
  accounts: Partial<Record<Role, Account>>;
  sessions: Partial<Record<Role, Session>>;
  authPrompt: { ws: Workspace; view?: string } | null;
  client: ClientInfo | null;
  intel: IntelInfo;
}

export interface ClientInfo { ip: string; country?: string; region?: string; city?: string; userAgent?: string; source: string }
export interface IntelInfo { fetchedAt?: string; count: number; sources: { name: string; ok: boolean; count: number; error?: string; url?: string }[]; status: 'loading' | 'live' | 'cached' | 'offline' }
export type AuthResult = { ok: true } | { ok: false; error: string; needReset?: boolean };

interface Actions {
  enter: (w: Workspace, view?: string) => void;
  createAccount: (role: Role, username: string, password: string) => Promise<AuthResult>;
  login: (role: Role, username: string, password: string) => Promise<AuthResult>;
  completeReset: (role: Role, username: string, oldPw: string, newPw: string) => Promise<AuthResult>;
  signOut: () => Promise<void>;
  deleteAccount: (role: Role) => Promise<void>;
  actor: () => string;
  emitPlatform: (e: { action: string; user?: string; message: string; meta?: Record<string, string | number | boolean> }) => Promise<void>;
  refreshIntel: () => Promise<void>;
  releaseControl: (id: string) => Promise<void>;
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
const INTEL_KEY = 'riskbyte.intel.v1';
const MONITOR_KEY = 'riskbyte.monitor.v1';
const DATA_CACHE = 'riskbyte-data-v1';
const CACHE_URL = '/__riskbyte__/state.json';
interface MonitorMeta { firstStartedAt: string; lastBeatAt?: string }
const initialMonitor: MonitorMeta = (() => {
  try {
    const m = JSON.parse(localStorage.getItem(MONITOR_KEY) || 'null') as MonitorMeta | null;
    return m?.firstStartedAt ? m : { firstStartedAt: new Date().toISOString() };
  } catch {
    return { firstStartedAt: new Date().toISOString() };
  }
})();
const previousBeat = initialMonitor.lastBeatAt;
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
  monitor: { lastScanAt: null, scans: 0, lastRejectAt: null, since: initialMonitor.firstStartedAt, lastGap: null },
  accounts: typeof localStorage !== 'undefined' ? loadAccounts() : {},
  sessions: typeof localStorage !== 'undefined' ? loadSessions() : {},
  authPrompt: null,
  client: null,
  intel: { count: 0, sources: [], status: 'loading' },

  set: (p) => set(p),

  actor: () => {
    const ws = get().workspace;
    if (!ws) return 'visitor';
    if (ws === 'demo') return 'simulator:operator';
    const role = WORKSPACE_ROLE[ws];
    return `${role}:${get().sessions[role]?.username ?? USERNAMES[role]}`;
  },

  emitPlatform: async (e) => {
    const c = get().client;
    const ev = {
      client: 'riskbyte', source: 'web', host: 'riskbyte-console', user: e.user, ip: c?.ip && c.ip !== 'unknown' ? c.ip : undefined,
      action: e.action, message: e.message,
      meta: { ...(c?.country ? { geo: [c.city, c.region, c.country].filter(Boolean).join(', ') } : {}), ...(c?.userAgent ? { ua: c.userAgent.slice(0, 120) } : {}), ...(e.meta ?? {}) },
      ts: new Date().toISOString(),
    };
    await request(apiCtx, 'POST', '/api/ingest', { token: TOKENS.ingest, body: { events: [ev] }, origin: 'ingest-api', actor: 'system:console' });
  },

  createAccount: async (role, username, password) => {
    const uname = username.trim().toLowerCase();
    if (!/^[a-z0-9._-]{3,32}$/.test(uname)) return { ok: false, error: 'Username: 3-32 characters (letters, digits, . _ -)' };
    const prob = passwordProblem(password);
    if (prob) return { ok: false, error: prob };
    if (get().accounts[role]) return { ok: false, error: 'An account already exists for this tier' };
    const now = new Date().toISOString();
    const acc: Account = { role, username: uname, ...(await hashPassword(password)), createdAt: now, passwordChangedAt: now, failed: 0, lastLoginAt: now, lastLoginIp: get().client?.ip };
    const accounts = { ...get().accounts, [role]: acc };
    saveAccounts(accounts);
    set({ accounts });
    await engine.record('auth.account_created', `${role} account "${uname}" created (${acc.algo}, ${acc.iterations} iterations) from ${get().client?.ip ?? 'unknown'}`, `${role}:${uname}`);
    await get().emitPlatform({ action: 'login_success', user: uname, message: `Account created and signed in to ${role} console`, meta: { role } });
    return startSession(role, uname);
  },

  login: async (role, username, password) => {
    const acc = get().accounts[role];
    if (!acc) return { ok: false, error: 'No account exists for this tier yet' };
    const now = Date.now();
    if (acc.lockedUntil && acc.lockedUntil > now) return { ok: false, error: `Account locked after ${MAX_FAILED} failed attempts. Try again in ${Math.ceil((acc.lockedUntil - now) / 1000)}s.` };
    const uname = username.trim().toLowerCase();
    const good = uname === acc.username && (await verifyPassword(acc, password));
    const ip = get().client?.ip ?? 'unknown';
    await get().emitPlatform({ action: good ? 'login_success' : 'login_failed', user: uname || '(blank)', message: good ? `Signed in to ${role} console` : `Failed sign-in to ${role} console`, meta: { role } });
    if (!good) {
      const failed = acc.failed + 1;
      const locked = failed >= MAX_FAILED;
      const next: Account = { ...acc, failed: locked ? 0 : failed, lockedUntil: locked ? now + LOCK_MS : acc.lockedUntil };
      const accounts = { ...get().accounts, [role]: next };
      saveAccounts(accounts);
      set({ accounts });
      get().track('failed sign-in', `${role} as "${uname}" from ${ip}`);
      if (locked) await engine.record('auth.lockout', `${role} account locked for ${LOCK_MS / 1000}s after ${MAX_FAILED} failed attempts from ${ip}`, 'system:auth');
      return { ok: false, error: locked ? `Too many failed attempts. Account locked for ${LOCK_MS / 1000}s.` : `Wrong username or password (${MAX_FAILED - failed} attempt${MAX_FAILED - failed === 1 ? '' : 's'} left before lockout)` };
    }
    if (engine.isControlled('disable_user', uname)) {
      await engine.record('auth.denied', `${role}:${uname} sign-in denied: account disabled by containment`, 'system:auth');
      return { ok: false, error: 'This account is disabled by a containment action. An administrator can release it under Containment.' };
    }
    if (ip !== 'unknown' && engine.isControlled('block_ip', ip)) {
      if (role !== 'admin') {
        await engine.record('auth.denied', `${role}:${uname} sign-in denied: source ${ip} is blocklisted`, 'system:auth');
        return { ok: false, error: `Your address ${ip} is on the blocklist. Sign in as Administrator to release it.` };
      }
      get().log('WARN', `riskbyte  break-glass: administrator signed in from blocklisted ${ip}`);
      await engine.record('auth.breakglass', `admin:${uname} signed in from blocklisted ${ip} (break-glass)`, 'system:auth');
    }
    const accounts = { ...get().accounts, [role]: { ...acc, failed: 0, lockedUntil: undefined, lastLoginAt: new Date().toISOString(), lastLoginIp: ip } };
    saveAccounts(accounts);
    set({ accounts });
    if (engine.isControlled('reset_password', uname)) return { ok: false, needReset: true, error: 'A containment action requires you to set a new password before signing in.' };
    await engine.record('auth.login', `${role}:${uname} signed in from ${ip}${get().client?.country ? ` (${get().client?.country})` : ''}`, `${role}:${uname}`);
    return startSession(role, uname);
  },

  completeReset: async (role, username, oldPw, newPw) => {
    const acc = get().accounts[role];
    const uname = username.trim().toLowerCase();
    if (!acc || uname !== acc.username || !(await verifyPassword(acc, oldPw))) return { ok: false, error: 'Current password is wrong' };
    const prob = passwordProblem(newPw);
    if (prob) return { ok: false, error: prob };
    if (newPw === oldPw) return { ok: false, error: 'Choose a different password' };
    const next: Account = { ...acc, ...(await hashPassword(newPw)), passwordChangedAt: new Date().toISOString(), failed: 0 };
    const accounts = { ...get().accounts, [role]: next };
    saveAccounts(accounts);
    set({ accounts });
    for (const c of (engine.data.controls ?? []).filter((x) => x.kind === 'reset_password' && x.value === uname)) await engine.releaseControl(c.id, `${role}:${uname}`);
    await engine.record('auth.password_changed', `${role}:${uname} changed password (credential reset completed)`, `${role}:${uname}`);
    await get().emitPlatform({ action: 'password_changed', user: uname, message: 'Password changed after enforced reset', meta: { role } });
    return startSession(role, uname);
  },

  signOut: async () => {
    const ws = get().workspace;
    if (ws && ws !== 'demo') {
      const role = WORKSPACE_ROLE[ws];
      const s = get().sessions[role];
      if (s) {
        const sessions = { ...get().sessions };
        delete sessions[role];
        saveSessions(sessions);
        set({ sessions });
        await engine.record('auth.logout', `${role}:${s.username} signed out`, `${role}:${s.username}`);
        await get().emitPlatform({ action: 'logout', user: s.username, message: `Signed out of ${role} console`, meta: { role } });
      }
    }
    get().leave();
  },

  deleteAccount: async (role) => {
    const acc = get().accounts[role];
    if (!acc) return;
    const accounts = { ...get().accounts };
    delete accounts[role];
    const sessions = { ...get().sessions };
    delete sessions[role];
    saveAccounts(accounts);
    saveSessions(sessions);
    set({ accounts, sessions });
    await engine.record('auth.account_deleted', `${role} account "${acc.username}" deleted (recovery) from ${get().client?.ip ?? 'unknown'}`, 'system:auth');
    get().toast(`${role} account deleted. Create a new one to continue.`);
  },

  releaseControl: async (id) => {
    get().track('released containment', id);
    await engine.releaseControl(id, get().actor());
    get().toast('Containment released', 'ok');
  },

  refreshIntel: async () => {
    try {
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), 15000);
      const res = await fetch('/api/intel', { signal: c.signal });
      clearTimeout(t);
      if (!res.ok || !(res.headers.get('content-type') ?? '').includes('json')) throw new Error(`HTTP ${res.status}`);
      const j = (await res.json()) as { fetchedAt: string; sources: IntelInfo['sources']; indicators: Indicator[] };
      if (!j.indicators?.length && j.sources?.every((x) => !x.ok)) throw new Error('all feeds failed');
      setLiveIntel(j.indicators, { fetchedAt: j.fetchedAt, sources: j.sources });
      write(INTEL_KEY, j);
      set({ intel: { fetchedAt: j.fetchedAt, sources: j.sources, count: j.indicators.length, status: 'live' } });
      get().log('OK', `riskbyte  threat intel refreshed: ${j.sources.map((x) => `${x.name} ${x.ok ? x.count : 'failed'}`).join(', ')}`);
    } catch (e) {
      const st = get().intel;
      set({ intel: { ...st, status: st.count ? 'cached' : 'offline' } });
      get().log('WARN', `riskbyte  threat intel feeds unreachable (${(e as Error).message}); using ${st.count ? 'cached feed data' : 'local list only'}`);
    }
  },

  enter: (w, view) => {
    if (w !== 'demo') {
      const role = WORKSPACE_ROLE[w];
      const s = get().sessions[role];
      if (!s || s.expiresAt <= Date.now()) {
        set({ authPrompt: { ws: w, view } });
        get().track('sign-in required', WORKSPACE_LABEL[w]);
        return;
      }
    }
    write(KEYS.session, { workspace: w });
    set({ workspace: w, view: view ?? VIEWS[w][0].id });
    get().track('opened workspace', `${WORKSPACE_LABEL[w]} → ${view ?? VIEWS[w][0].id}`);
    get().log('INFO', `session opened workspace=${w} role=${WORKSPACE_ROLE[w]} token=${TOKENS[WORKSPACE_ROLE[w]]}`);
  },
  leave: () => {
    get().track('left workspace', get().workspace ? WORKSPACE_LABEL[get().workspace!] : '');
    try { localStorage.removeItem(KEYS.session); } catch { /* ignore */ }
    set({ workspace: null, view: '', authPrompt: null });
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
    const actor = get().actor();
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
    const res = await request(apiCtx, method, path, { ...opts, actor: get().actor(), token: ws ? TOKENS[WORKSPACE_ROLE[ws]] : undefined });
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
        const orgs = getOrgs().filter((x) => !x.platform);
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
    await engine.repair(get().actor());
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
    const org = await engine.addOrg(o, get().actor());
    get().toast(`${org.name} onboarded (id ${org.id})`, 'ok');
    return true;
  },
  removeOrg: async (id) => {
    get().track('offboarded organization', id);
    const ok = await engine.removeOrg(id, get().actor());
    get().toast(ok ? 'Organization offboarded. History is kept.' : 'At least one organization is required', ok ? 'ok' : 'error');
  },
  clearAllData: () => {
    get().track('factory reset');
    wiping = true;
    clearAll();
    try { ['riskbyte.accounts.v1', 'riskbyte.sessions.v1', INTEL_KEY, MONITOR_KEY].forEach((k) => localStorage.removeItem(k)); } catch { /* ignore */ }
    if (typeof caches !== 'undefined') caches.delete(DATA_CACHE).catch(() => undefined);
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
      const prevControls = useStore.getState().data.controls?.length ?? 0;
      const prevAudit = useStore.getState().audit;
      useStore.setState({ data, audit });
      if ((data.controls?.length ?? 0) !== prevControls) setTimeout(revalidateSessions, 0);
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
  installLifecycleHooks();
  loadCachedIntel();
  if (!loaded.data) await restoreFromCache();
  if (useStore.getState().logs.length) useStore.getState().log('INFO', `riskbyte  restored ${useStore.getState().logs.length} log lines from previous session`);
  try { localStorage.removeItem('riskbyte.state.v1'); localStorage.removeItem('riskbyte.checklist.v1'); localStorage.removeItem('riskbyte.engine.v1'); } catch { /* ignore */ }
  await engine.init();
  if (previousBeat && Date.now() - Date.parse(previousBeat) > 90_000) {
    const to = new Date().toISOString();
    useStore.setState((s) => ({ monitor: { ...s.monitor, lastGap: { from: previousBeat, to } } }));
    await engine.recordGap(previousBeat, to);
  }
  write(MONITOR_KEY, { firstStartedAt: initialMonitor.firstStartedAt, lastBeatAt: new Date().toISOString() });
  await identifyClient();
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
  useStore.getState().refreshIntel();
  setInterval(() => useStore.getState().refreshIntel(), 3600_000);
  revalidateSessions();
  await useStore.getState().emitPlatform({ action: 'session_start', message: 'Console opened', meta: { since: initialMonitor.firstStartedAt } });
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
        write(MONITOR_KEY, { firstStartedAt: initialMonitor.firstStartedAt, lastBeatAt: new Date().toISOString() });
        mirrorToCache();
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

// ---------------- sessions ----------------
function startSession(role: Role, username: string): AuthResult {
  const st = useStore.getState();
  const sessions = { ...st.sessions, [role]: newSession(role, username) };
  saveSessions(sessions);
  const target = st.authPrompt;
  useStore.setState({ sessions, authPrompt: null });
  if (target) useStore.getState().enter(target.ws, target.view);
  return { ok: true };
}

/** Ends sessions that a containment action now forbids (disabled account, blocklisted address). */
function revalidateSessions() {
  const st = useStore.getState();
  const ip = st.client?.ip;
  let changed = false;
  const sessions = { ...st.sessions };
  for (const role of Object.keys(sessions) as Role[]) {
    const s = sessions[role]!;
    const disabled = engine.isControlled('disable_user', s.username);
    const blocked = !!ip && ip !== 'unknown' && role !== 'admin' && engine.isControlled('block_ip', ip);
    if (disabled || blocked || s.expiresAt <= Date.now()) {
      delete sessions[role];
      changed = true;
      st.log('WARN', `riskbyte  session ended for ${role}:${s.username} (${disabled ? 'account disabled by containment' : blocked ? `source ${ip} blocklisted` : 'expired'})`);
    }
  }
  if (!changed) return;
  saveSessions(sessions);
  useStore.setState({ sessions });
  const ws = st.workspace;
  if (ws && ws !== 'demo' && !sessions[WORKSPACE_ROLE[ws]]) {
    useStore.getState().leave();
    useStore.getState().toast('Your session was ended by a containment action or expired.', 'error');
  }
}

// ---------------- durable storage ----------------
/** Writes everything to localStorage immediately and mirrors the platform data into Cache Storage. */
let wiping = false;
export function flushNow() {
  if (wiping) return;
  const st = useStore.getState();
  write(KEYS.state, st.data);
  write(KEYS.logs, st.logs.slice(-800));
  write(MONITOR_KEY, { firstStartedAt: st.monitor.since, lastBeatAt: new Date().toISOString() } satisfies MonitorMeta);
  mirrorToCache();
}

let lastMirror = 0;
function mirrorToCache(force = false) {
  if (typeof caches === 'undefined') return;
  if (!force && Date.now() - lastMirror < 15_000) return;
  lastMirror = Date.now();
  const body = JSON.stringify({ savedAt: new Date().toISOString(), data: useStore.getState().data });
  caches.open(DATA_CACHE).then((c) => c.put(CACHE_URL, new Response(body, { headers: { 'Content-Type': 'application/json' } }))).catch(() => undefined);
}

async function restoreFromCache(): Promise<boolean> {
  if (typeof caches === 'undefined') return false;
  try {
    const c = await caches.open(DATA_CACHE);
    const r = await c.match(CACHE_URL);
    if (!r) return false;
    const j = (await r.json()) as { savedAt: string; data: EngineData };
    if (j?.data?.version !== 2) return false;
    await engine.load(j.data);
    useStore.getState().log('OK', `riskbyte  restored platform data from Cache Storage (saved ${j.savedAt})`);
    return true;
  } catch {
    return false;
  }
}

function installLifecycleHooks() {
  if (typeof window === 'undefined') return;
  window.addEventListener('pagehide', flushNow);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') flushNow(); });
  window.addEventListener('beforeunload', flushNow);
  // Real client telemetry about this console.
  window.addEventListener('online', () => useStore.getState().emitPlatform({ action: 'network_online', message: 'Console regained network connectivity' }));
  window.addEventListener('offline', () => useStore.getState().emitPlatform({ action: 'network_offline', message: 'Console lost network connectivity' }));
  window.addEventListener('error', (e) => useStore.getState().emitPlatform({ action: 'client_error', message: `Uncaught error: ${String(e.message).slice(0, 200)}` }));
  window.addEventListener('unhandledrejection', (e) => useStore.getState().emitPlatform({ action: 'client_error', message: `Unhandled rejection: ${String((e as PromiseRejectionEvent).reason).slice(0, 200)}` }));
}

async function identifyClient() {
  try {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 4000);
    const res = await fetch('/api/whoami', { signal: c.signal });
    clearTimeout(t);
    if (!res.ok || !(res.headers.get('content-type') ?? '').includes('json')) throw new Error();
    const j = (await res.json()) as ClientInfo;
    useStore.setState({ client: { ...j, userAgent: j.userAgent ?? navigator.userAgent } });
  } catch {
    useStore.setState({ client: { ip: 'unknown', userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : undefined, source: 'unavailable' } });
  }
  const c = useStore.getState().client!;
  useStore.getState().log('INFO', `riskbyte  console session from ${c.ip}${c.city || c.country ? ` (${[c.city, c.country].filter(Boolean).join(', ')})` : ''}`);
}

function loadCachedIntel() {
  try {
    const j = JSON.parse(localStorage.getItem(INTEL_KEY) || 'null') as { fetchedAt: string; sources: IntelInfo['sources']; indicators: Indicator[] } | null;
    if (!j?.indicators) return;
    setLiveIntel(j.indicators, { fetchedAt: j.fetchedAt, sources: j.sources });
    useStore.setState({ intel: { fetchedAt: j.fetchedAt, sources: j.sources, count: j.indicators.length, status: 'cached' } });
  } catch { /* ignore */ }
}
