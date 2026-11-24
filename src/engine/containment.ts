import type { Action, RiskEvent, Rule } from './types';

/** Picks the containment target for a rule from the triggering event. */
export function proposeContainment(rule: Rule, e: RiskEvent): { action: Action; target: string } {
  const target = (e[rule.target] as string | undefined) ?? e.host ?? e.user ?? e.ip ?? 'unknown';
  return { action: rule.action, target };
}
