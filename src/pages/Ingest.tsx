import { useMemo, useState } from 'react';
import { useStore } from '../store/store';
import type { ClientId, RiskEvent } from '../engine/types';
import { MAX_BATCH, SOURCES } from '../engine/normalize';
import { Button, ClientBadge, EmptyState, fmtTime, relTime, useTick } from '../components/ui';
import { Console } from '../components/Console';
import { Bars } from './Analyst';

export default function IngestWorkspace() {
  const view = useStore((s) => s.view);
  if (view === 'stream') return <Stream />;
  if (view === 'send') return <Send />;
  if (view === 'console') return <Console />;
  return <Sources />;
}

function Sources() {
  useTick(5000);
  const events = useStore((s) => s.data.events);
  const counters = useStore((s) => s.data.counters);
  const orgs = useStore((s) => s.data.orgs);
  const now = Date.now();
  const last5 = events.filter((e) => now - Date.parse(e.ts) <= 5 * 60_000).length;
  const rows = useMemo(() => {
    const m = new Map<string, { org: ClientId; source: string; n: number; last: string }>();
    for (const e of events) {
      const k = `${e.client}|${e.source}`;
      const r = m.get(k) ?? { org: e.client, source: e.source, n: 0, last: e.ts };
      r.n += 1;
      if (e.ts > r.last) r.last = e.ts;
      m.set(k, r);
    }
    return [...m.values()].sort((a, b) => b.last.localeCompare(a.last));
  }, [events]);
  const silent = orgs.filter((o) => !events.some((e) => e.client === o.id));

  return (
    <>
      <section className="kpis">
        <div className="kpi"><span className="label">Events · last 5 min</span><span className="v">{last5}</span><span className="s">{(last5 / 300).toFixed(2)} events/s</span></div>
        <div className="kpi"><span className="label">Total processed</span><span className="v">{counters.totalIngested}</span><span className="s">{counters.batches} batches</span></div>
        <div className="kpi"><span className="label">Active collectors</span><span className="v">{rows.filter((r) => now - Date.parse(r.last) <= 10 * 60_000).length}</span><span className="s">seen in last 10 min</span></div>
        <div className="kpi"><span className="label">Pipeline latency</span><span className="v">{counters.batches ? (counters.totalMs / counters.batches).toFixed(1) : '0.0'}<span style={{ fontSize: '.5em' }}> ms</span></span><span className="s">normalize → detect → audit</span></div>
      </section>
      <div className="cols-2e">
        <section className="panel">
          <div className="panel-head"><h3>Endpoints</h3></div>
          <div className="table-wrap">
            <table className="tbl">
              <caption className="sr-only">Ingest endpoints</caption>
              <thead><tr><th>Endpoint</th><th>Status</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td className="mono">POST /api/ingest</td><td><span className="pill st-executed">Ready</span></td><td className="small">JSON batches up to {MAX_BATCH} events, bearer token</td></tr>
                <tr><td className="mono">udp://0.0.0.0:5514</td><td><span className="pill st-executed">Listening</span></td><td className="small">Syslog collector (simulated; browsers cannot open UDP sockets)</td></tr>
              </tbody>
            </table>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head"><h3>Volume by source type</h3></div>
          <div className="panel-body"><Bars rows={SOURCES.map((s) => ({ label: s, n: events.filter((e) => e.source === s).length }))} /></div>
        </section>
      </div>
      <section className="panel">
        <div className="panel-head"><h3>Collectors</h3><div className="right"><span className="pill chip">{rows.length} reporting</span></div></div>
        {rows.length === 0 && silent.length === orgs.length ? <EmptyState icon="⇪" title="No telemetry received yet">Collectors appear as soon as the first event from an organization arrives.</EmptyState> : (
          <div className="table-wrap">
            <table className="tbl">
              <caption className="sr-only">Collectors by organization and source</caption>
              <thead><tr><th>Organization</th><th>Source</th><th>Events</th><th>Last event</th><th>Status</th></tr></thead>
              <tbody>
                {rows.map((r) => {
                  const active = now - Date.parse(r.last) <= 10 * 60_000;
                  return (
                    <tr key={r.org + r.source}>
                      <td><ClientBadge client={r.org} /></td><td className="mono">{r.source}</td><td>{r.n}</td><td className="nowrap">{relTime(r.last)}</td>
                      <td><span className={`pill ${active ? 'st-executed' : 'st-dismissed'}`}>{active ? 'Active' : 'Idle'}</span></td>
                    </tr>
                  );
                })}
                {silent.map((o) => (
                  <tr key={o.id}><td><ClientBadge client={o.id} /></td><td className="muted">—</td><td>0</td><td className="muted">never</td><td><span className="pill st-triaged">Awaiting data</span></td></tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function Stream() {
  const events = useStore((s) => s.data.events);
  const orgs = useStore((s) => s.data.orgs);
  const [frozen, setFrozen] = useState<RiskEvent[] | null>(null);
  const [org, setOrg] = useState<ClientId | 'all'>('all');
  const [q, setQ] = useState('');
  const source = frozen ?? events;
  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return [...source].reverse().filter((e) => (org === 'all' || e.client === org) &&
      (!needle || [e.id, e.host, e.user, e.ip, e.domain, e.process, e.action, e.message].some((v) => v?.toLowerCase().includes(needle)))).slice(0, 300);
  }, [source, org, q]);
  return (
    <section className="panel">
      <div className="panel-head">
        <Button variant={frozen ? 'primary' : 'secondary'} size="sm" onClick={() => setFrozen(frozen ? null : [...events])}>{frozen ? '▶ Resume' : '⏸ Pause'}</Button>
        <select className="select" style={{ width: 220, padding: '7px 36px 7px 12px' }} value={org} onChange={(e) => setOrg(e.target.value)} aria-label="Organization">
          <option value="all">All organizations</option>
          {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
        </select>
        <input className="input" style={{ width: 240, padding: '7px 12px' }} placeholder="Search host, user, ip, message…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search events" />
        <div className="right"><span className="small muted">{frozen ? `Paused · ${events.length - frozen.length} new` : 'Live · newest first · up to 300'}</span></div>
      </div>
      {list.length === 0 ? <EmptyState icon="≋" title="No events">Events appear here the moment they are accepted.</EmptyState> : (
        <div className="table-wrap tall">
          <table className="tbl">
            <caption className="sr-only">Normalized events</caption>
            <thead><tr><th>ID</th><th>Time</th><th>Organization</th><th>Source</th><th>Host</th><th>User</th><th>Process</th><th>Action</th><th>IP</th><th>Message</th></tr></thead>
            <tbody>{list.map((e) => (
              <tr key={e.id}>
                <td className="mono nowrap">{e.id}{e.origin === 'demo' && <div><span className="pill chip" style={{ fontSize: 10, padding: '1px 8px', marginTop: 4 }}>simulated</span></div>}</td>
                <td className="mono nowrap">{fmtTime(e.ts)}</td><td><ClientBadge client={e.client} /></td><td>{e.source}</td>
                <td className="mono">{e.host ?? '-'}</td><td className="mono">{e.user ?? '-'}</td><td className="mono">{e.process ?? '-'}</td>
                <td className="mono nowrap">{e.action}</td><td className="mono nowrap">{e.ip ?? '-'}</td>
                <td className="cmd">{e.message}{e.domain ? ` [${e.domain}]` : ''}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}

const sample = (org: string) => JSON.stringify({
  events: [{ client: org, source: 'syslog', host: 'srv-app-01', user: 'svc.web', ip: '10.0.4.12', action: 'login_success', message: 'sshd: Accepted publickey for svc.web', ts: new Date().toISOString() }],
}, null, 2);

function jsonError(text: string, err: Error): string {
  const lc = /line (\d+) column (\d+)/.exec(err.message);
  if (lc) return `Invalid JSON at line ${lc[1]}, column ${lc[2]}`;
  const m = /position (\d+)/.exec(err.message);
  if (m) {
    const pos = Number(m[1]);
    const before = text.slice(0, pos);
    return `Invalid JSON at line ${before.split('\n').length}, column ${pos - before.lastIndexOf('\n')}`;
  }
  return `Invalid JSON: ${err.message}`;
}

function Send() {
  const api = useStore((s) => s.api);
  const orgs = useStore((s) => s.data.orgs);
  const [text, setText] = useState(() => sample(orgs[0]?.id ?? 'meezan'));
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ status: number; body: unknown } | null>(null);
  const [busy, setBusy] = useState(false);
  const send = async () => {
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch (e) { setError(jsonError(text, e as Error)); return; }
    setError(null);
    setBusy(true);
    const res = await api('POST', '/api/ingest', { body: parsed, origin: 'ingest-api' });
    setBusy(false);
    setResult(res);
  };
  return (
    <div className="cols-2e">
      <section className="panel">
        <div className="panel-head"><h3>Request</h3><div className="right"><code className="small">POST /api/ingest · Bearer dev-ingest</code></div></div>
        <div className="panel-body stack">
          <div className="row">
            <span className="small muted">Template for:</span>
            {orgs.map((o) => <Button key={o.id} size="sm" variant="secondary" onClick={() => { setText(sample(o.id)); setResult(null); setError(null); }}>{o.name}</Button>)}
          </div>
          <textarea className="textarea" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-label="Request body" aria-invalid={!!error} />
          {error && <div className="banner bad small" role="alert">{error}</div>}
          <div className="row"><Button onClick={send} busy={busy}>Send</Button><span className="small muted">Fields: client (organization id), source ({SOURCES.join(', ')}), action, and optional ts, host, user, ip, domain, process, message, meta.</span></div>
        </div>
      </section>
      <section className="panel" aria-live="polite">
        <div className="panel-head"><h3>Response</h3>{result && <div className="right"><span className={`pill ${result.status < 300 ? 'st-executed' : 'sev-CRITICAL'}`}>{result.status}</span></div>}</div>
        <div className="panel-body">
          {result ? <pre className="yaml" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{JSON.stringify(result.body, null, 2)}</pre> : <p className="muted">The API response appears here.</p>}
        </div>
      </section>
    </div>
  );
}
