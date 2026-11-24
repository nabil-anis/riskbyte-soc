import { describe, it, expect } from 'vitest';
import { heuristicTriage, heuristicScore, verdictFor } from '../engine/heuristic';
import type { Alert, RiskEvent } from '../engine/types';
import { SCENARIOS } from '../data/scenarios';

const alert = (o: Partial<Alert> = {}): Alert => ({
  id: 'A-0042', ruleId: 'rb-001', client: 'meezan', severity: 'MEDIUM', title: 'Repeated failed logins (brute force)', ts: '2026-11-25T10:00:00Z',
  ip: '1.2.3.4', status: 'new', caseId: 'C-0001', eventIds: [], intelHits: [], proposed: { action: 'block_ip', target: '1.2.3.4' }, ...o,
});

describe('heuristic triage', () => {
  it('scores per the formula', () => {
    const hit = { value: '1.2.3.4', type: 'ip' as const, category: 'x', confidence: 0.9, note: '' };
    const night = { meta: { hour: 3 } } as unknown as RiskEvent;
    expect(heuristicScore(alert(), [], false)).toBe(45);
    expect(heuristicScore(alert({ intelHits: [hit] }), [], true)).toBe(65);
    expect(heuristicScore(alert({ severity: 'CRITICAL', intelHits: [hit, hit, hit] }), [night], true)).toBe(80 + 30 + 8 + 5);
    expect(verdictFor(75)).toBe('MALICIOUS');
    expect(verdictFor(74)).toBe('SUSPICIOUS');
    expect(verdictFor(44)).toBe('BENIGN');
  });
  it('is deterministic', () => {
    const a = heuristicTriage(alert(), []);
    const b = heuristicTriage(alert(), []);
    expect({ ...a, ms: 0 }).toEqual({ ...b, ms: 0 });
    expect(a.steps).toHaveLength(4);
  });
  it('uses the fixed confidences for the 12 scenarios', () => {
    const expected: Record<string, number> = { meezan_phish: 96, meezan_anomalous_login: 93, meezan_brute: 88, meezan_transfer: 94, shu_phish: 95, shu_brute: 87, shu_ransomware: 98, shu_data_export: 94, contour_malware: 95, contour_ssh_brute: 89, contour_vpn: 92, contour_code_download: 94 };
    for (const s of SCENARIOS) {
      const t = heuristicTriage(alert({ ruleId: s.ruleId, scenarioId: s.id, severity: s.severity }), []);
      expect(t.confidence).toBe(expected[s.id]);
      expect(t.verdict).toBe('MALICIOUS');
    }
  });
});
