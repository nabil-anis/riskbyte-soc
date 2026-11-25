import type { Alert, RiskEvent, Triage } from './types';
import { heuristicTriage } from './heuristic';
import { callGemini, callGeminiServer, parseGeminiResponse, SYSTEM_INSTRUCTION, GeminiError } from './gemini';
import { redact, unredact } from './redact';
import { ruleById } from '../data/rules';
import { clientName } from '../data/clients';

export interface TriageConfig {
  apiKey: string;
  model: string;
  /** use the server-side proxy (GEMINI_API_KEY on the server) when no browser key is set */
  server?: boolean;
}

/** Builds the evidence document sent to the model (before redaction). */
export function evidenceFor(alert: Alert, events: RiskEvent[]) {
  const rule = ruleById(alert.ruleId);
  return {
    alert: {
      id: alert.id,
      rule: `${alert.ruleId} ${alert.title}`,
      severity: alert.severity,
      mitre: rule?.mitre,
      organisation: clientName(alert.client),
      host: alert.host,
      user: alert.user,
      source_ip: alert.ip,
      proposed_action: `${alert.proposed.action} ${alert.proposed.target}`,
    },
    rule_description: rule?.description,
    threat_intel_hits: alert.intelHits.map((i) => ({ indicator: i.value, type: i.type, category: i.category, confidence: i.confidence })),
    events: events.map((e) => ({ ts: e.ts, source: e.source, host: e.host, user: e.user, ip: e.ip, domain: e.domain, process: e.process, action: e.action, message: e.message, meta: e.meta })),
  };
}

export function redactEvidence(alert: Alert, events: RiskEvent[]) {
  const evidence = evidenceFor(alert, events);
  const users = [alert.user, ...events.map((e) => e.user)].filter(Boolean) as string[];
  const hosts = [alert.host, ...events.map((e) => e.host)].filter(Boolean) as string[];
  return redact(JSON.stringify(evidence, null, 2), { users, hosts, orgs: [clientName(alert.client)] });
}

/** Gemini when a key is set; otherwise (or on any failure) the deterministic heuristic. Never throws. */
export async function triage(alert: Alert, events: RiskEvent[], cfg: TriageConfig, repeatEntity = false): Promise<Triage> {
  if (!cfg.apiKey && !cfg.server) return heuristicTriage(alert, events, repeatEntity);
  const t0 = performance.now();
  const r = redactEvidence(alert, events);
  try {
    const json = cfg.apiKey
      ? await callGemini({ apiKey: cfg.apiKey, model: cfg.model, system: SYSTEM_INSTRUCTION, userText: r.text })
      : await callGeminiServer({ model: cfg.model, userText: r.text });
    const parsed = parseGeminiResponse(json);
    return {
      provider: 'gemini',
      model: cfg.model,
      verdict: parsed.verdict,
      confidence: parsed.confidence,
      summary: unredact(parsed.summary, r.map),
      steps: parsed.steps.map((s) => unredact(s, r.map)),
      redacted: true,
      redactionCounts: r.counts,
      ms: Math.round(performance.now() - t0),
    };
  } catch (e) {
    const reason = e instanceof GeminiError ? e.short : 'unexpected error';
    const h = heuristicTriage(alert, events, repeatEntity, reason);
    return { ...h, ms: Math.round(performance.now() - t0) };
  }
}
