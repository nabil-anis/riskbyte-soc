import { describe, it, expect } from 'vitest';
import { SCENARIOS, scenarioEvents } from '../data/scenarios';
import { makeEngine } from './helpers';
import { request } from '../engine/api';

describe('scenarios run end to end through the API', () => {
  for (const s of SCENARIOS) {
    it(`${s.id} fires ${s.ruleId} and proposes ${s.proposed.action} ${s.proposed.target}`, async () => {
      const { engine, ctx } = makeEngine();
      await engine.init();
      const res = await request(ctx, 'POST', '/api/ingest', { token: 'dev-analyst', body: { events: scenarioEvents(s) }, origin: 'demo', scenarioId: s.id });
      expect(res.status).toBe(200);
      const alerts = engine.data.alerts;
      expect(alerts).toHaveLength(1);
      const a = alerts[0];
      expect(a.ruleId).toBe(s.ruleId);
      expect(a.severity).toBe(s.severity);
      expect(a.proposed).toEqual(s.proposed);
      expect(a.intelHits.map((i) => i.value).sort()).toEqual([...s.intel].sort());
      expect(a.status).toBe('triaged');
      expect(a.triage?.verdict).toBe('MALICIOUS');
      expect(a.triage?.confidence).toBe(s.confidence);
      expect(engine.auditStatus.intact).toBe(true);
    });
  }

  it('approve writes an audit block and is idempotent; dismiss after approve is 409', async () => {
    const { engine, ctx } = makeEngine();
    await engine.init();
    await request(ctx, 'POST', '/api/ingest', { token: 'dev-analyst', body: { events: scenarioEvents(SCENARIOS[0]) }, scenarioId: SCENARIOS[0].id });
    const id = engine.data.alerts[0].id;
    const before = engine.data.audit.length;
    const r1 = await request(ctx, 'POST', `/api/alerts/${id}/approve`, { token: 'dev-analyst' });
    expect(r1.status).toBe(200);
    expect(engine.data.audit.length).toBe(before + 1);
    const last = engine.data.audit[engine.data.audit.length - 1];
    expect(last.kind).toBe('containment.approved');
    expect(last.actor).toBe('analyst:soc.analyst');
    const r2 = await request(ctx, 'POST', `/api/alerts/${id}/approve`, { token: 'dev-analyst' });
    expect(r2.status).toBe(200);
    expect(engine.data.audit.length).toBe(before + 1);
    const r3 = await request(ctx, 'POST', `/api/alerts/${id}/dismiss`, { token: 'dev-analyst' });
    expect(r3.status).toBe(409);
    expect(engine.data.cases[0].status).toBe('closed');
  });

  it('running the same scenario twice within 60s dedupes instead of opening a duplicate', async () => {
    const { engine, ctx } = makeEngine();
    await engine.init();
    const s = SCENARIOS[2];
    await request(ctx, 'POST', '/api/ingest', { token: 'dev-analyst', body: { events: scenarioEvents(s) }, scenarioId: s.id });
    const r = await request(ctx, 'POST', '/api/ingest', { token: 'dev-analyst', body: { events: scenarioEvents(s, Date.now() + 2000) }, scenarioId: s.id });
    expect(engine.data.alerts).toHaveLength(1);
    expect((r.body as { deduped: unknown[] }).deduped).toHaveLength(1);
  });
});

describe('agent behaviour', () => {
  it('records a timeline and waits for approval by default', async () => {
    const { engine, ctx } = makeEngine();
    await engine.init();
    await request(ctx, 'POST', '/api/ingest', { token: 'dev-ingest', body: { events: scenarioEvents(SCENARIOS[0]) } });
    const a = engine.data.alerts[0];
    expect(a.timeline.map((s) => s.kind)).toEqual(['detect', 'correlate', 'enrich', 'case', 'triage', 'propose', 'await']);
    expect(a.status).toBe('triaged');
  });
  it('auto-executes when policy allows and confidence is high enough', async () => {
    const { Engine } = await import('../engine/engineState');
    const { request: req } = await import('../engine/api');
    const engine = new Engine({
      log: () => {}, onChange: () => {},
      triageConfig: () => ({ apiKey: '', model: 'x' }),
      policy: () => ({ modes: { isolate_host: 'approve', block_ip: 'approve', disable_user: 'approve', reset_password: 'auto' }, minConfidence: 90 }),
    });
    await engine.init();
    const ctx = { engine, isEngineOn: () => true, provider: () => ({ provider: 'heuristic' as const, model: 'h' }), log: () => {} };
    await req(ctx, 'POST', '/api/ingest', { token: 'dev-ingest', body: { events: scenarioEvents(SCENARIOS[0]) }, scenarioId: SCENARIOS[0].id });
    const a = engine.data.alerts[0];
    expect(a.status).toBe('executed');
    expect(a.outcome?.auto).toBe(true);
    expect(engine.data.audit.some((b) => b.kind === 'containment.auto_executed' && b.actor === 'ai:riskbyte-agent')).toBe(true);
    expect((await (await import('../engine/audit')).verifyChain(engine.data.audit)).intact).toBe(true);
  });
  it('onboards a new organization that can then receive telemetry', async () => {
    const { engine, ctx } = makeEngine();
    await engine.init();
    const org = await engine.addOrg({ name: 'Acme Health', sector: 'Healthcare' }, 'admin:soc.admin');
    expect(org.id).toBe('acme-health');
    const r = await request(ctx, 'POST', '/api/ingest', { token: 'dev-ingest', body: { events: [{ client: 'acme-health', source: 'vpn', user: 'dr.x', ip: '198.51.100.99', action: 'login_success', meta: { geo: 'Foreign' }, message: 'vpn' }] } });
    expect(r.status).toBe(200);
    expect(engine.data.alerts[0].client).toBe('acme-health');
  });
});
