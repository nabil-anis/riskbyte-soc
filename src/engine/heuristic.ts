import type { Alert, RiskEvent, Severity, Triage, Verdict } from './types';
import { ruleById } from '../data/rules';
import { scenarioById } from '../data/scenarios';
import { clientName } from '../data/clients';
import { ACTION_PLAIN } from '../data/copy';

const BASE: Record<Severity, number> = { LOW: 20, MEDIUM: 45, HIGH: 65, CRITICAL: 80 };

/** Small, stable offset (0-6) derived from the alert id. */
export function stableOffset(id: string): number {
  let h = 0;
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return h % 7;
}

export function isOffHours(events: RiskEvent[]): boolean {
  return events.some((e) => {
    const h = Number(e.meta?.hour);
    return Number.isFinite(h) && (h < 7 || h > 20);
  });
}

export function heuristicScore(alert: Alert, events: RiskEvent[], repeatEntity: boolean): number {
  return BASE[alert.severity] + Math.min(30, alert.intelHits.length * 15) + (isOffHours(events) ? 8 : 0) + (repeatEntity ? 5 : 0);
}

export const verdictFor = (score: number): Verdict => (score >= 75 ? 'MALICIOUS' : score >= 45 ? 'SUSPICIOUS' : 'BENIGN');

export function heuristicTriage(alert: Alert, events: RiskEvent[], repeatEntity = false, fallbackReason?: string): Triage {
  const started = performance.now();
  const rule = ruleById(alert.ruleId);
  const score = heuristicScore(alert, events, repeatEntity);
  const scenario = alert.scenarioId ? scenarioById(alert.scenarioId) : undefined;
  const fixed = scenario && scenario.ruleId === alert.ruleId ? scenario.confidence : undefined;
  const verdict: Verdict = fixed !== undefined ? 'MALICIOUS' : verdictFor(score);
  const confidence = fixed ?? Math.min(99, score + stableOffset(alert.id));
  const entity = alert.proposed.target;
  const intel = alert.intelHits.length
    ? `It also matches ${alert.intelHits.length} known-bad indicator${alert.intelHits.length > 1 ? 's' : ''} (${alert.intelHits.map((i) => `${i.value}, ${i.category}`).join('; ')}).`
    : 'No threat-intel indicator matched, so the verdict rests on the behaviour alone.';
  const summary = `${rule?.title ?? alert.title} was detected for ${entity} at ${clientName(alert.client)}: ${rule?.plain.toLowerCase() ?? ''} ${intel} Recommended response: ${alert.proposed.action} ${entity}, pending human approval.`;
  const steps = [
    `Review the ${events.length} correlated event(s) for ${entity} and confirm the timeline matches ${alert.ruleId} (${rule?.mitre ?? ''}).`,
    alert.intelHits.length
      ? `Confirm the indicator match: ${alert.intelHits.map((i) => i.value).join(', ')} (confidence ${Math.round(Math.max(...alert.intelHits.map((i) => i.confidence)) * 100)}%).`
      : 'Check the source address and domain against fresh threat-intel feeds.',
    `Contact the owner of ${entity} to rule out legitimate activity${isOffHours(events) ? ', noting this happened outside business hours' : ''}.`,
    `If confirmed, approve ${alert.proposed.action} ${entity} to ${ACTION_PLAIN[alert.proposed.action]}${alert.ruleId === 'rb-010' ? ' and hold the pending payment batch' : ''}.`,
  ];
  return {
    provider: 'heuristic',
    model: 'riskbyte-heuristic-v1',
    verdict,
    confidence,
    summary,
    steps,
    redacted: false,
    fallbackReason,
    ms: Math.max(1, Math.round(performance.now() - started)),
  };
}
