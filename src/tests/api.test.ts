import { describe, it, expect } from 'vitest';
import { request, ROUTES, matchRoute, normalizePath } from '../engine/api';
import { makeEngine } from './helpers';
import { scenarioEvents, SCENARIOS } from '../data/scenarios';
import { constantTimeEqual, roleForToken } from '../engine/auth';
import { generate, ATTACK_TYPES } from '../engine/generators';

describe('mock API', () => {
  it('has 12 routes and every one resolves', () => {
    expect(ROUTES).toHaveLength(12);
    for (const r of ROUTES) expect(matchRoute(r.method, r.pattern.replace(':id', 'A-0001'))?.route).toBe(r);
  });
  it('normalizes trailing slashes and query strings', async () => {
    expect(normalizePath('/api/alerts/?client=meezan')).toBe('/api/alerts');
    const { ctx, engine } = makeEngine();
    await engine.init();
    expect((await request(ctx, 'GET', '/api/alerts/?severity=high', { token: 'dev-analyst' })).status).toBe(200);
    expect((await request(ctx, 'GET', '/healthz/', { token: 'dev-ingest' })).status).toBe(200);
  });
  it('enforces the role matrix', async () => {
    const { ctx, engine } = makeEngine();
    await engine.init();
    await request(ctx, 'POST', '/api/ingest', { token: 'dev-ingest', body: { events: scenarioEvents(SCENARIOS[0]) } });
    const id = engine.data.alerts[0].id;
    const deny = await request(ctx, 'POST', `/api/alerts/${id}/approve`, { token: 'dev-ingest' });
    expect(deny.status).toBe(403);
    expect((deny.body as { detail: string }).detail).toBe("Role 'ingest' cannot approve containment");
    expect((await request(ctx, 'POST', `/api/alerts/${id}/dismiss`, { token: 'dev-ingest' })).status).toBe(403);
    expect((await request(ctx, 'GET', '/api/alerts', { token: 'dev-ingest' })).status).toBe(403);
    expect((await request(ctx, 'POST', '/api/demo/reset', { token: 'dev-analyst' })).status).toBe(403);
    expect((await request(ctx, 'POST', '/api/demo/reset', { token: 'dev-admin' })).status).toBe(200);
    expect(engine.data.alerts).toHaveLength(0);
    expect(engine.data.audit.map((b) => b.kind)).toEqual(['ledger.genesis', 'system.reset']);
    expect((await request(ctx, 'GET', '/api/stats')).status).toBe(401);
    const nf = await request(ctx, 'GET', '/api/nope', { token: 'dev-admin' });
    expect(nf.status).toBe(404);
    expect((nf.body as { routes: string[] }).routes).toHaveLength(12);
  });
  it('returns 413 above 1000 events and 400 on bad payloads', async () => {
    const { ctx, engine } = makeEngine();
    await engine.init();
    const big = Array.from({ length: 1001 }, () => ({ client: 'shu', source: 'web', action: 'x', message: '' }));
    expect((await request(ctx, 'POST', '/api/ingest', { token: 'dev-ingest', body: { events: big } })).status).toBe(413);
    const bad = await request(ctx, 'POST', '/api/ingest', { token: 'dev-ingest', body: { events: [{ client: 'nope' }] } });
    expect(bad.status).toBe(400);
    expect((bad.body as { problems: string[] }).problems.length).toBeGreaterThan(0);
  });
  it('constant-time comparison works', () => {
    expect(constantTimeEqual('dev-admin', 'dev-admin')).toBe(true);
    expect(constantTimeEqual('dev-admin', 'dev-admim')).toBe(false);
    expect(constantTimeEqual('dev', 'dev-admin')).toBe(false);
    expect(roleForToken('dev-analyst')).toBe('analyst');
  });
  it('every playground generator produces events that raise an alert', async () => {
    for (const client of ['meezan', 'shu', 'contour'] as const) {
      for (const t of ATTACK_TYPES) {
        const { ctx, engine } = makeEngine();
        await engine.init();
        const evs = generate(t.id, client, '', 3).map(({ delayMs: _d, ...e }) => e);
        await request(ctx, 'POST', '/api/ingest', { token: 'dev-admin', body: { events: evs }, origin: 'playground' });
        expect(engine.data.alerts.length, `${client}/${t.id}`).toBeGreaterThan(0);
      }
    }
  });
});
