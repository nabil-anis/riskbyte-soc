import { describe, it, expect, vi, afterEach } from 'vitest';
import { handleGemini } from '../../api/_core';
import { classifyLog } from '../engine/types';
import { baselineBatch } from '../engine/baseline';
import { DEFAULT_ORGS } from '../data/clients';
import { makeEngine } from './helpers';
import { request } from '../engine/api';

afterEach(() => vi.unstubAllGlobals());

describe('server Gemini proxy', () => {
  it('reports whether GEMINI_API_KEY is configured', async () => {
    expect((await handleGemini('GET', undefined, 'k')).body).toMatchObject({ configured: true });
    expect((await handleGemini('GET', undefined, '')).body).toMatchObject({ configured: false });
    expect((await handleGemini('POST', '{}', '')).status).toBe(501);
  });
  it('adds the key server-side and enforces the triage request shape', async () => {
    let headers: Record<string, string> = {};
    let sent: any = null;
    vi.stubGlobal('fetch', vi.fn(async (_u: string, init: RequestInit) => {
      headers = init.headers as Record<string, string>;
      sent = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ candidates: [] }), { status: 200 });
    }));
    const r = await handleGemini('POST', JSON.stringify({ mode: 'triage', model: 'gemini-2.5-flash', userText: 'evidence' }), 'server-key');
    expect(r.status).toBe(200);
    expect(headers['x-goog-api-key']).toBe('server-key');
    expect(sent.systemInstruction.parts[0].text).toContain('SOC triage assistant');
    expect(sent.generationConfig.responseSchema.required).toContain('verdict');
    expect((await handleGemini('POST', JSON.stringify({ model: 'bad model/../x', userText: 'x' }), 'k')).status).toBe(400);
    expect((await handleGemini('POST', JSON.stringify({ userText: 'x'.repeat(30_000) }), 'k')).status).toBe(400);
  });
});

describe('24/7 monitoring', () => {
  it('baseline telemetry is scanned without raising alerts or bloating the ledger', async () => {
    const { engine, ctx } = makeEngine();
    await engine.init();
    const blocks = engine.data.audit.length;
    for (let i = 0; i < 60; i++) {
      await request(ctx, 'POST', '/api/ingest', { token: 'dev-ingest', body: { events: baselineBatch(DEFAULT_ORGS, 6) }, quiet: true, auditMode: 'onAlert', silent: true });
    }
    expect(engine.data.counters.totalIngested).toBe(360);
    expect(engine.data.alerts).toHaveLength(0);
    expect(engine.data.audit.length).toBe(blocks);
  });
  it('classifies log lines by source', () => {
    expect(classifyLog('user analyst:soc.analyst clicked "Approve"')).toBe('user');
    expect(classifyLog('POST /api/ingest 200 accepted=2 role=ingest')).toBe('api');
    expect(classifyLog('audit block #3 kind=x')).toBe('audit');
    expect(classifyLog('agent A-0001: verdict=MALICIOUS')).toBe('agent');
    expect(classifyLog('scan e-0001..e-0004 · 4 events')).toBe('pipeline');
  });
});
