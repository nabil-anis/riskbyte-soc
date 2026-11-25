import type { Indicator, RiskEvent } from './types';
import { INDICATORS } from '../data/indicators';

/** Live indicators from real feeds (abuse.ch Feodo Tracker, OpenPhish), merged with the local list. */
let live = new Map<string, Indicator>();
let liveMeta: { fetchedAt?: string; sources: { name: string; ok: boolean; count: number; error?: string; url?: string }[] } = { sources: [] };

export function setLiveIntel(list: Indicator[], meta: typeof liveMeta) {
  live = new Map(list.map((i) => [i.value.toLowerCase(), i]));
  liveMeta = meta;
}
export const liveIntel = () => ({ indicators: [...live.values()], ...liveMeta });

export function lookup(value: string | undefined): Indicator | undefined {
  if (!value) return undefined;
  const v = value.toLowerCase();
  const local = INDICATORS.find((i) => i.value === v);
  if (local) return local;
  const hit = live.get(v);
  if (hit) return hit;
  // A domain matches if it is a subdomain of a known-bad domain.
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(v)) {
    const parts = v.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = live.get(parts.slice(i).join('.'));
      if (parent) return { ...parent, value: v, note: `subdomain of ${parent.value} · ${parent.note}` };
    }
  }
  return undefined;
}

/** Match every IP and domain on the given events against the indicator list (deduplicated). */
export function matchIntel(events: RiskEvent[]): Indicator[] {
  const hits = new Map<string, Indicator>();
  for (const e of events) {
    for (const v of [e.ip, e.domain]) {
      const hit = lookup(v);
      if (hit) hits.set(hit.value, hit);
    }
  }
  return [...hits.values()];
}

const PRIVATE = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^127\./];

/** Anything that is not an internal/private address is untrusted for these rules. */
export function isUntrustedIp(ip: string | undefined): boolean {
  if (!ip) return false;
  return !PRIVATE.some((r) => r.test(ip));
}
