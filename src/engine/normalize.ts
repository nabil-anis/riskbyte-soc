import type { ClientId, EventSource, Origin, RiskEvent } from './types';

export const CLIENT_IDS: ClientId[] = ['meezan', 'shu', 'contour'];
export const SOURCES: EventSource[] = ['syslog', 'vpn', 'proxy', 'endpoint', 'web', 'gateway', 'git', 'payments'];
export const MAX_BATCH = 1000;

export interface ValidationResult {
  ok: boolean;
  problems: string[];
}

/** Validates a raw ingest batch. Each item needs client, source, action and message. */
export function validateBatch(events: unknown): ValidationResult {
  const problems: string[] = [];
  if (!Array.isArray(events)) return { ok: false, problems: ['"events" must be an array of event objects'] };
  if (events.length === 0) problems.push('"events" is empty; send at least one event');
  events.slice(0, MAX_BATCH).forEach((raw, i) => {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      problems.push(`events[${i}] must be an object`);
      return;
    }
    const e = raw as Record<string, unknown>;
    if (!CLIENT_IDS.includes(e.client as ClientId)) problems.push(`events[${i}].client must be one of ${CLIENT_IDS.join(', ')}`);
    if (!SOURCES.includes(e.source as EventSource)) problems.push(`events[${i}].source must be one of ${SOURCES.join(', ')}`);
    if (typeof e.action !== 'string' || !e.action) problems.push(`events[${i}].action is required (e.g. login_failed)`);
    if (e.message !== undefined && typeof e.message !== 'string') problems.push(`events[${i}].message must be a string`);
    if (e.ts !== undefined && Number.isNaN(Date.parse(String(e.ts)))) problems.push(`events[${i}].ts is not a valid ISO date`);
    if (e.meta !== undefined && (typeof e.meta !== 'object' || e.meta === null)) problems.push(`events[${i}].meta must be an object`);
  });
  return { ok: problems.length === 0, problems: problems.slice(0, 12) };
}

const low = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim().toLowerCase() : undefined);
const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim() : undefined);

export function eventId(n: number) {
  return `e-${String(n).padStart(4, '0')}`;
}

/** Normalizes one validated raw event into a RiskEvent. */
export function normalizeEvent(raw: Record<string, unknown>, n: number, defaultOrigin: Origin): RiskEvent {
  const ts = raw.ts ? new Date(String(raw.ts)).toISOString() : new Date().toISOString();
  const meta = { ...((raw.meta as Record<string, string | number | boolean>) ?? {}) };
  if (meta.hour === undefined) meta.hour = new Date(ts).getHours();
  const origin = (['demo', 'playground', 'dispatcher', 'ingest-api'] as Origin[]).includes(raw.origin as Origin) ? (raw.origin as Origin) : defaultOrigin;
  return {
    id: eventId(n),
    ts,
    client: raw.client as ClientId,
    source: raw.source as EventSource,
    host: low(raw.host),
    user: low(raw.user),
    ip: str(raw.ip),
    domain: low(raw.domain),
    process: str(raw.process),
    action: String(raw.action).trim().toLowerCase(),
    message: str(raw.message) ?? '',
    meta,
    origin,
  };
}
