import type { Indicator, RiskEvent } from './types';
import { INDICATORS } from '../data/indicators';

export function lookup(value: string | undefined): Indicator | undefined {
  if (!value) return undefined;
  const v = value.toLowerCase();
  return INDICATORS.find((i) => i.value === v);
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
