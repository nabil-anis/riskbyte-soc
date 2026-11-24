import { describe, it, expect, vi, afterEach } from 'vitest';
import { triage } from '../engine/triage';
import type { Alert, RiskEvent } from '../engine/types';

const alert: Alert = {
  id: 'A-0001', ruleId: 'rb-006', client: 'meezan', severity: 'HIGH', title: 'Phishing link click then external login', ts: '2026-11-25T10:00:00Z',
  host: 'ibanking-web-02', user: 'customer.tariq', ip: '203.0.113.88', status: 'new', caseId: 'C-0001', eventIds: ['e-0001'],
  intelHits: [{ value: '203.0.113.88', type: 'ip', category: 'phishing proxy', confidence: 0.91, note: '' }],
  proposed: { action: 'reset_password', target: 'customer.tariq' }, scenarioId: 'meezan_phish', timeline: [],
};
const events: RiskEvent[] = [{ id: 'e-0001', ts: alert.ts, client: 'meezan', source: 'web', host: 'ibanking-web-02', user: 'customer.tariq', ip: '203.0.113.88', action: 'login_success', message: 'Login from untrusted proxy', origin: 'demo' }];

afterEach(() => vi.unstubAllGlobals());

describe('gemini triage', () => {
  it('sends only redacted evidence and maps tokens back in the result', async () => {
    let sent = '';
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
      sent = String(init.body);
      const reply = { verdict: 'MALICIOUS', confidence: 140, summary: '[REDACTED_USER_1] logged in from [REDACTED_IP_1].', steps: ['1. Reset [REDACTED_USER_1]', 'Block [REDACTED_IP_1]', 'Review [REDACTED_HOST_1]'] };
      return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(reply) }] } }] }), { status: 200 });
    }));
    const t = await triage(alert, events, { apiKey: 'test-key', model: 'gemini-2.5-flash' });
    expect(sent).not.toContain('customer.tariq');
    expect(sent).not.toContain('203.0.113.88');
    expect(sent).not.toContain('ibanking-web-02');
    expect(sent).toContain('responseSchema');
    expect(t.provider).toBe('gemini');
    expect(t.confidence).toBe(100); // clamped
    expect(t.summary).toBe('customer.tariq logged in from 203.0.113.88.');
    expect(t.steps[0]).toBe('Reset customer.tariq');
    expect(t.redacted).toBe(true);
  });
  it('falls back to the heuristic on HTTP errors and malformed output', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { message: 'API key not valid' } }), { status: 400 })));
    const t1 = await triage(alert, events, { apiKey: 'bad', model: 'gemini-2.5-flash' });
    expect(t1.provider).toBe('heuristic');
    expect(t1.fallbackReason).toContain('400');
    expect(t1.confidence).toBe(96);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: 'not json' }] } }] }), { status: 200 })));
    const t2 = await triage(alert, events, { apiKey: 'k', model: 'm' });
    expect(t2.fallbackReason).toBe('malformed JSON');
  });
  it('uses the heuristic when no key is set', async () => {
    const t = await triage(alert, events, { apiKey: '', model: 'gemini-2.5-flash' });
    expect(t.provider).toBe('heuristic');
    expect(t.fallbackReason).toBeUndefined();
  });
});
