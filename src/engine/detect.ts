import type { Alert, RiskEvent, Rule } from './types';
import { RULES } from '../data/rules';

export const DEDUPE_SEC = 60;
export const WINDOW_SEC = 15 * 60;

export interface Detection {
  rule: Rule;
  event: RiskEvent;
  entity: string;
  triggering: RiskEvent[];
}

export interface DedupeHit {
  rule: Rule;
  entity: string;
  alertId: string;
  event: RiskEvent;
}

export const entityOf = (rule: Rule, e: RiskEvent): string | undefined => e[rule.entity] as string | undefined;

/** Sliding window: events of the same client within WINDOW_SEC of `e`. */
export function windowFor(e: RiskEvent, all: RiskEvent[]): RiskEvent[] {
  const t = new Date(e.ts).getTime();
  return all.filter((x) => x.client === e.client && Math.abs(new Date(x.ts).getTime() - t) <= WINDOW_SEC * 1000);
}

/**
 * Evaluates every rule against each new event (with the sliding window of all stored events).
 * Dedupes: the same rule for the same client+entity does not fire twice within 60 seconds.
 */
export function detect(newEvents: RiskEvent[], allEvents: RiskEvent[], existingAlerts: Alert[], rules: Rule[] = RULES): { fired: Detection[]; deduped: DedupeHit[] } {
  const fired: Detection[] = [];
  const deduped: DedupeHit[] = [];
  const recent: { ruleId: string; client: string; entity: string; t: number; alertId: string }[] = existingAlerts.map((a) => ({
    ruleId: a.ruleId,
    client: a.client,
    entity: alertEntity(a, rules),
    t: new Date(a.ts).getTime(),
    alertId: a.id,
  }));

  for (const e of newEvents) {
    const w = windowFor(e, allEvents);
    for (const rule of rules) {
      const triggering = rule.match(e, w);
      if (!triggering) continue;
      const entity = entityOf(rule, e);
      if (!entity) continue;
      const t = new Date(e.ts).getTime();
      const dup = recent.find((r) => r.ruleId === rule.id && r.client === e.client && r.entity === entity && Math.abs(t - r.t) <= DEDUPE_SEC * 1000);
      if (dup) {
        if (!deduped.some((d) => d.alertId === dup.alertId && d.rule.id === rule.id)) deduped.push({ rule, entity, alertId: dup.alertId, event: e });
        continue;
      }
      fired.push({ rule, event: e, entity, triggering });
      recent.push({ ruleId: rule.id, client: e.client, entity, t, alertId: `pending-${fired.length}` });
    }
  }
  return { fired, deduped };
}

export function alertEntity(a: Alert, rules: Rule[] = RULES): string {
  const rule = rules.find((r) => r.id === a.ruleId);
  const key = rule?.entity ?? 'host';
  return (a[key] as string | undefined) ?? a.host ?? a.user ?? a.ip ?? '';
}

/** Events in the window that share the alert's host, user or ip (correlated telemetry). */
export function relatedEvents(d: Detection, all: RiskEvent[]): RiskEvent[] {
  const w = windowFor(d.event, all);
  const ids = new Set(d.triggering.map((x) => x.id));
  const byIp = d.rule.entity === 'ip';
  const keys = [d.event.host, d.event.user].filter(Boolean);
  const out = [...d.triggering];
  for (const x of w) {
    if (ids.has(x.id) || x.meta?.baseline) continue;
    const near = Math.abs(new Date(x.ts).getTime() - new Date(d.event.ts).getTime()) <= 10 * 60 * 1000;
    const linked = byIp ? x.ip === d.event.ip : (x.host && keys.includes(x.host)) || (x.user && keys.includes(x.user));
    if (near && linked) {
      out.push(x);
      ids.add(x.id);
    }
  }
  return out.sort((a, b) => a.ts.localeCompare(b.ts));
}
