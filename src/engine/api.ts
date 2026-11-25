import type { Role } from './types';
import { roleForToken, actorFor } from './auth';
import type { Engine } from './engineState';
import { MAX_BATCH } from './normalize';
import { RULES } from '../data/rules';
import { LICENSE } from './license';

export type Method = 'GET' | 'POST';
export interface ApiResponse<T = unknown> {
  status: number;
  body: T;
}

export interface RouteDef {
  method: Method;
  pattern: string;
  roles: Role[];
}

/** The 12 routes of the in-browser mock API and the roles allowed to call them. */
export const ROUTES: RouteDef[] = [
  { method: 'GET', pattern: '/healthz', roles: ['ingest', 'analyst', 'admin'] },
  { method: 'GET', pattern: '/api/stats', roles: ['analyst', 'admin'] },
  { method: 'GET', pattern: '/api/license', roles: ['ingest', 'analyst', 'admin'] },
  { method: 'GET', pattern: '/api/alerts', roles: ['analyst', 'admin'] },
  { method: 'GET', pattern: '/api/alerts/:id', roles: ['analyst', 'admin'] },
  { method: 'POST', pattern: '/api/alerts/:id/approve', roles: ['analyst', 'admin'] },
  { method: 'POST', pattern: '/api/alerts/:id/dismiss', roles: ['analyst', 'admin'] },
  { method: 'GET', pattern: '/api/cases', roles: ['analyst', 'admin'] },
  { method: 'GET', pattern: '/api/audit', roles: ['analyst', 'admin'] },
  { method: 'GET', pattern: '/api/events', roles: ['ingest', 'analyst', 'admin'] },
  { method: 'POST', pattern: '/api/ingest', roles: ['ingest', 'analyst', 'admin'] },
  { method: 'POST', pattern: '/api/demo/reset', roles: ['admin'] },
];

export const ROUTE_LIST = ROUTES.map((r) => `${r.method} ${r.pattern}`);

/** Strips query strings and trailing slashes. */
export function normalizePath(path: string): string {
  let p = path.split('?')[0].split('#')[0];
  if (p.length > 1) p = p.replace(/\/+$/, '');
  return p || '/';
}

export function matchRoute(method: Method, path: string): { route: RouteDef; params: Record<string, string> } | undefined {
  const parts = normalizePath(path).split('/');
  for (const route of ROUTES) {
    if (route.method !== method) continue;
    const pp = route.pattern.split('/');
    if (pp.length !== parts.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < pp.length; i++) {
      if (pp[i].startsWith(':')) params[pp[i].slice(1)] = decodeURIComponent(parts[i]);
      else if (pp[i] !== parts[i]) { ok = false; break; }
    }
    if (ok) return { route, params };
  }
  return undefined;
}

const DENY_TEXT: Record<string, string> = {
  'POST /api/alerts/:id/approve': 'approve containment',
  'POST /api/alerts/:id/dismiss': 'dismiss alerts',
  'POST /api/demo/reset': 'reset demo data',
};

export interface ApiContext {
  engine: Engine;
  isEngineOn: () => boolean;
  provider: () => { provider: 'gemini' | 'heuristic'; model: string };
  log: (level: 'INFO' | 'WARN' | 'OK' | 'ERROR' | 'ALERT', text: string) => void;
}

export interface RequestOptions {
  token?: string;
  body?: unknown;
  /** where the request came from (for event origin) */
  origin?: 'demo' | 'playground' | 'dispatcher' | 'ingest-api';
  scenarioId?: string;
  silent?: boolean;
  quiet?: boolean;
  auditMode?: 'always' | 'onAlert';
}

/** Mock REST API that runs in the browser. Every call returns {status, body} and is logged. */
export async function request(ctx: ApiContext, method: Method, path: string, opts: RequestOptions = {}): Promise<ApiResponse> {
  const role = roleForToken(opts.token) ?? 'none';
  let logged = false;
  // Ingest logs its 200 as soon as events are accepted (before AI triage finishes).
  const onStaged = (o: { accepted: number }) => {
    logged = true;
    if (opts.silent) return;
    ctx.log('INFO', `${method} ${normalizePath(path)} 200 accepted=${o.accepted} role=${role}`);
  };
  const res = await handle(ctx, method, path, { ...opts, onStaged } as RequestOptions & { onStaged: typeof onStaged });
  if (!logged && (!opts.silent || res.status >= 400)) {
    ctx.log(res.status < 300 ? (method === 'POST' && path.includes('/approve') ? 'OK' : 'INFO') : res.status >= 500 ? 'ERROR' : 'WARN', `${method} ${normalizePath(path)} ${res.status} role=${role}`);
  }
  return res;
}

async function handle(ctx: ApiContext, method: Method, path: string, opts: RequestOptions & { onStaged?: (o: { accepted: number }) => void }): Promise<ApiResponse> {
  const m = matchRoute(method, path);
  if (!m) return { status: 404, body: { error: 'route not found', route: `${method} ${normalizePath(path)}`, suggestion: 'Check the path', routes: ROUTE_LIST } };
  const role = roleForToken(opts.token);
  if (!role) return { status: 401, body: { error: 'unauthorized', detail: 'Missing or invalid bearer token. Use dev-ingest, dev-analyst or dev-admin.' } };
  const key = `${m.route.method} ${m.route.pattern}`;
  if (!m.route.roles.includes(role)) {
    return { status: 403, body: { error: 'forbidden', detail: `Role '${role}' cannot ${DENY_TEXT[key] ?? `call ${key}`}` } };
  }
  const { engine } = ctx;
  const d = engine.data;
  const id = m.params.id;

  switch (key) {
    case 'GET /healthz':
      return { status: 200, body: { ok: true, engine: ctx.isEngineOn() ? 'on' : 'off' } };
    case 'GET /api/stats':
      return { status: 200, body: { ...engine.stats(), ...ctx.provider(), engine: ctx.isEngineOn() ? 'on' : 'off', rules: RULES.length } };
    case 'GET /api/license':
      return { status: 200, body: LICENSE };
    case 'GET /api/alerts': {
      const q = new URLSearchParams(path.split('?')[1] ?? '');
      let list = [...d.alerts].reverse();
      if (q.get('client')) list = list.filter((a) => a.client === q.get('client'));
      if (q.get('severity')) list = list.filter((a) => a.severity === q.get('severity')!.toUpperCase());
      if (q.get('status')) list = list.filter((a) => a.status === q.get('status'));
      return { status: 200, body: { count: list.length, alerts: list } };
    }
    case 'GET /api/alerts/:id': {
      const a = d.alerts.find((x) => x.id === id);
      if (!a) return { status: 404, body: { error: 'alert not found', alertId: id } };
      return { status: 200, body: { ...a, events: d.events.filter((e) => a.eventIds.includes(e.id)) } };
    }
    case 'POST /api/alerts/:id/approve':
    case 'POST /api/alerts/:id/dismiss': {
      if (!ctx.isEngineOn()) return { status: 503, body: { error: 'engine off', detail: 'Turn the Engine on first' } };
      return engine.decide(id, key.endsWith('approve') ? 'approve' : 'dismiss', actorFor(role));
    }
    case 'GET /api/cases':
      return { status: 200, body: { count: d.cases.length, cases: [...d.cases].reverse() } };
    case 'GET /api/audit':
      return { status: 200, body: { status: engine.auditStatus, blocks: d.audit } };
    case 'GET /api/events':
      return { status: 200, body: { count: d.events.length, events: [...d.events].reverse().slice(0, 200) } };
    case 'POST /api/ingest': {
      if (!ctx.isEngineOn()) return { status: 503, body: { error: 'engine off', detail: 'Turn the Engine on first' } };
      const b = opts.body as { events?: unknown } | unknown[] | undefined;
      const events = Array.isArray(b) ? b : (b as { events?: unknown })?.events;
      if (!Array.isArray(events)) return { status: 400, body: { error: 'bad request', problems: ['Body must be {"events": [ ... ]} or an array of events'] } };
      if (events.length > MAX_BATCH) return { status: 413, body: { error: 'payload too large', detail: `Batch has ${events.length} events; the limit is ${MAX_BATCH} per request. Split it into smaller batches.` } };
      try {
        const out = await engine.ingest(events, { origin: opts.origin ?? 'ingest-api', scenarioId: opts.scenarioId, actor: actorFor(role), onStaged: opts.onStaged, quiet: opts.quiet, auditMode: opts.auditMode });
        return { status: 200, body: out };
      } catch (e) {
        const err = e as Error & { problems?: string[] };
        if (err.problems) return { status: 400, body: { error: 'bad request', problems: err.problems } };
        return { status: 500, body: { error: 'internal error', detail: err.message } };
      }
    }
    case 'POST /api/demo/reset':
      await engine.reset(actorFor(role));
      return { status: 200, body: { ok: true, detail: 'Demo data reset' } };
  }
  return { status: 404, body: { error: 'route not found', route: key, suggestion: 'Check the path', routes: ROUTE_LIST } };
}
