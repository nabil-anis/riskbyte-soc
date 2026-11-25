import { describe, it, expect } from 'vitest';
import { makeEngine } from './helpers';
import { request } from '../engine/api';
import { scenarioEvents, SCENARIOS } from '../data/scenarios';
import { hashPassword, verifyPassword, passwordProblem, type Account } from '../engine/accounts';
import { verifyLicense, LICENSE, LICENSE_SIGNATURE } from '../engine/license';
import { parseLogText } from '../engine/logparse';
import { setLiveIntel, lookup } from '../engine/intel';

const ingest = (ctx: ReturnType<typeof makeEngine>['ctx'], events: unknown[]) => request(ctx, 'POST', '/api/ingest', { token: 'dev-ingest', body: { events } });

describe('containment is enforced', () => {
  it('blocks traffic from a blocklisted IP after approval, so the attack stops firing', async () => {
    const { engine, ctx } = makeEngine();
    await engine.init();
    await ingest(ctx, scenarioEvents(SCENARIOS[2]));
    const a = engine.data.alerts[0];
    expect(a.proposed).toEqual({ action: 'block_ip', target: '1.2.3.4' });
    await request(ctx, 'POST', `/api/alerts/${a.id}/approve`, { token: 'dev-analyst', actor: 'analyst:nabil' });
    expect(engine.isControlled('block_ip', '1.2.3.4')).toBe(true);
    expect(engine.data.audit.at(-1)!.actor).toBe('analyst:nabil');
    const r = await ingest(ctx, scenarioEvents(SCENARIOS[2], Date.now() + 120_000));
    expect((r.body as { enforced: number }).enforced).toBe(6);
    expect(engine.data.events.slice(-6).every((e) => e.action === 'connection_blocked')).toBe(true);
    expect(engine.data.alerts).toHaveLength(1); // no new brute-force alert: the traffic was dropped
  });
  it('denies logins for disabled users and quarantines isolated hosts; release lifts it', async () => {
    const { engine, ctx } = makeEngine();
    await engine.init();
    await ingest(ctx, scenarioEvents(SCENARIOS[1])); // disable_user staff.farooq
    await request(ctx, 'POST', `/api/alerts/${engine.data.alerts[0].id}/approve`, { token: 'dev-analyst' });
    await ingest(ctx, [{ client: 'meezan', source: 'web', user: 'staff.farooq', ip: '10.0.0.1', action: 'login_success', message: 'x' }]);
    expect(engine.data.events.at(-1)!.action).toBe('login_denied');
    await ingest(ctx, scenarioEvents(SCENARIOS.find((s) => s.id === 'shu_ransomware')!));
    const ransom = engine.data.alerts.find((x) => x.ruleId === 'rb-007')!;
    await request(ctx, 'POST', `/api/alerts/${ransom.id}/approve`, { token: 'dev-analyst' });
    await ingest(ctx, [{ client: 'shu', source: 'gateway', host: 'lab-pc-18', action: 'dns_query', domain: 'example.org', message: 'dns' }]);
    expect(engine.data.events.at(-1)!.action).toBe('network_quarantined');
    const ctl = engine.data.controls!.find((c) => c.kind === 'isolate_host')!;
    await engine.releaseControl(ctl.id, 'admin:x');
    await ingest(ctx, [{ client: 'shu', source: 'gateway', host: 'lab-pc-18', action: 'dns_query', domain: 'example.org', message: 'dns' }]);
    expect(engine.data.events.at(-1)!.action).toBe('dns_query');
    expect(engine.data.audit.some((b) => b.kind === 'containment.released')).toBe(true);
  });
});

describe('real platform telemetry', () => {
  it('five failed console logins from one IP fire the brute-force rule on the Riskbyte Platform org', async () => {
    const { engine, ctx } = makeEngine();
    await engine.init();
    const fails = Array.from({ length: 5 }, (_, i) => ({ client: 'riskbyte', source: 'web', host: 'riskbyte-console', user: 'soc.admin', ip: '39.40.1.2', action: 'login_failed', message: 'Failed sign-in', ts: new Date(Date.now() + i * 1000).toISOString() }));
    await ingest(ctx, fails);
    expect(engine.data.alerts[0]).toMatchObject({ ruleId: 'rb-001', client: 'riskbyte', proposed: { action: 'block_ip', target: '39.40.1.2' } });
  });
});

describe('accounts', () => {
  it('hashes with PBKDF2 and verifies only the right password', async () => {
    const h = await hashPassword('correct horse 42');
    expect(h.algo).toBe('pbkdf2-sha256');
    expect(h.hash).toHaveLength(64);
    const acc: Account = { role: 'admin', username: 'a', ...h, createdAt: '', passwordChangedAt: '', failed: 0 };
    expect(await verifyPassword(acc, 'correct horse 42')).toBe(true);
    expect(await verifyPassword(acc, 'correct horse 43')).toBe(false);
    expect(passwordProblem('short1')).not.toBeNull();
    expect(passwordProblem('longenough')).not.toBeNull();
    expect(passwordProblem('longenough1')).toBeNull();
  });
});

describe('signed license', () => {
  it('verifies the shipped signature and rejects a tampered license', async () => {
    expect((await verifyLicense()).signature).toBe('valid');
    expect((await verifyLicense({ ...LICENSE, hostQuota: 9999 }, LICENSE_SIGNATURE)).signature).toBe('invalid');
  });
});

describe('log parsing', () => {
  it('maps real auth.log lines to events and detects a brute force', async () => {
    const lines = Array.from({ length: 6 }, (_, i) => `Nov 25 10:12:0${i} web01 sshd[1${i}]: Failed password for invalid user admin from 45.13.7.9 port 5${i}000 ssh2`);
    lines.push('Nov 25 10:13:00 web01 sshd[99]: Accepted publickey for deploy from 10.0.0.5 port 50000 ssh2');
    lines.push('Nov 25 10:14:00 web01 useradd[100]: new user: name=backdoor, UID=1002, GID=1002');
    const r = parseLogText(lines.join('\n'), 'meezan', new Date('2026-11-25T12:00:00'));
    expect(r.format).toBe('syslog');
    expect(r.events.filter((e) => e.action === 'login_failed')).toHaveLength(6);
    expect(r.events[0]).toMatchObject({ user: 'admin', ip: '45.13.7.9', host: 'web01' });
    expect(r.events.some((e) => e.action === 'login_success' && e.user === 'deploy')).toBe(true);
    expect(r.events.some((e) => e.action === 'user_created' && e.user === 'backdoor')).toBe(true);
    const { engine, ctx } = makeEngine();
    await engine.init();
    await ingest(ctx, r.events);
    expect(engine.data.alerts.some((a) => a.ruleId === 'rb-001' && a.ip === '45.13.7.9')).toBe(true);
  });
  it('parses JSON and NDJSON', () => {
    expect(parseLogText('[{"source":"vpn","action":"login_success"}]', 'shu').events[0]).toMatchObject({ client: 'shu', source: 'vpn' });
    expect(parseLogText('{"action":"a"}\n{"action":"b"}\nnot json', 'shu')).toMatchObject({ format: 'ndjson', skipped: 1 });
  });
});

describe('live threat intel', () => {
  it('matches feed indicators and subdomains', () => {
    setLiveIntel([{ value: 'evil-login.example', type: 'domain', category: 'phishing (live)', confidence: 0.9, note: 'x', source: 'OpenPhish' }], { sources: [] });
    expect(lookup('evil-login.example')?.source).toBe('OpenPhish');
    expect(lookup('www.evil-login.example')?.note).toContain('subdomain of');
    expect(lookup('fine.example')).toBeUndefined();
    setLiveIntel([], { sources: [] });
  });
});
