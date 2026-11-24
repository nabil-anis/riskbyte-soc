import { useMemo, useState } from 'react';
import { useStore } from '../store/store';
import type { ClientId, RiskEvent } from '../engine/types';
import { CLIENTS } from '../data/clients';
import { MAX_BATCH } from '../engine/normalize';
import { Button, ClientBadge, EmptyState, fmtTime } from '../components/ui';
import { useEngineGate } from '../components/gates';

const now = () => new Date().toISOString();
const PRESETS: { name: string; desc: string; body: () => unknown }[] = [
  {
    name: 'Syslog Authentication', desc: '6 failed SSH logins from one IP',
    body: () => ({ events: Array.from({ length: 6 }, (_, i) => ({ client: 'contour', source: 'syslog', host: 'ci-build-01', user: 'jenkins_svc', ip: '1.2.3.4', action: 'login_failed', message: `sshd: Failed password for jenkins_svc (attempt ${i + 1})`, ts: new Date(Date.now() + i * 3000).toISOString() })) }),
  },
  {
    name: 'Encoded PowerShell', desc: 'hidden -enc command on a laptop',
    body: () => ({ events: [{ client: 'contour', source: 'endpoint', host: 'dev-ws-077', user: 'dev.sana', process: 'powershell.exe', action: 'process_start', message: 'powershell.exe -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==', ts: now() }] }),
  },
  {
    name: 'Phishing Link Click', desc: 'click on a spoofed bank page, then a proxy login',
    body: () => ({ events: [
      { client: 'meezan', source: 'proxy', host: 'gw-sms-01', user: 'customer.nadia', domain: 'meezan-fake-login.com', ip: '203.0.113.88', action: 'link_click', message: "Clicked link in SMS from 'MeezanBank'", ts: now() },
      { client: 'meezan', source: 'web', host: 'ibanking-web-02', user: 'customer.nadia', ip: '203.0.113.88', action: 'login_success', message: 'Login from untrusted proxy shortly after link click', ts: new Date(Date.now() + 2000).toISOString() },
    ] }),
  },
];

export default function Ingest() {
  const [sub, setSub] = useState<'stream' | 'dispatch'>('stream');
  const engineOn = useStore((s) => s.engineOn);
  const total = useStore((s) => s.data.counters.totalIngested);
  const batches = useStore((s) => s.data.counters.batches);
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="label">Telemetry</div>
          <h1 style={{ marginTop: 10 }}>Telemetry Ingest 📡</h1>
          <p>Where logs enter Riskbyte. Watch the raw stream, or hand-craft a batch and send it to the in-browser REST API yourself.</p>
        </div>
      </div>
      <section className="grid g3" aria-label="Ingest health">
        <div className="card metric">
          <div className="label">Syslog UDP :5514</div>
          <div className={`num sm ${engineOn ? 'ok' : ''}`}>{engineOn ? 'Listening' : 'Stopped'}</div>
          <span className="small muted">Simulated: a website cannot open UDP ports.</span>
        </div>
        <div className="card metric">
          <div className="label">REST · POST /api/ingest</div>
          <div className={`num sm ${engineOn ? 'ok' : ''}`}>{engineOn ? 'Ready' : 'Offline'}</div>
          <span className="small muted">In-browser API, up to {MAX_BATCH} events per batch.</span>
        </div>
        <div className="card metric">
          <div className="label">Total processed logs</div>
          <div className="num">{total}</div>
          <span className="small muted">{batches} batch{batches === 1 ? '' : 'es'}</span>
        </div>
      </section>
      <div className="seg" role="tablist" aria-label="Ingest views" style={{ alignSelf: 'flex-start' }}>
        <button role="tab" type="button" aria-selected={sub === 'stream'} onClick={() => setSub('stream')}>Live Telemetry Stream</button>
        <button role="tab" type="button" aria-selected={sub === 'dispatch'} onClick={() => setSub('dispatch')}>Direct Event Dispatcher</button>
      </div>
      {sub === 'stream' ? <Stream /> : <Dispatcher />}
    </div>
  );
}

function Stream() {
  const events = useStore((s) => s.data.events);
  const [paused, setPaused] = useState<RiskEvent[] | null>(null);
  const [client, setClient] = useState<ClientId | 'all'>('all');
  const source = paused ?? events;
  const list = useMemo(() => [...source].reverse().filter((e) => client === 'all' || e.client === client).slice(0, 300), [source, client]);
  return (
    <section className="card pad-sm stack" aria-label="Live telemetry stream">
      <div className="row between">
        <div className="row">
          <Button variant={paused ? 'primary' : 'secondary'} size="sm" onClick={() => setPaused(paused ? null : [...events])}>{paused ? '▶ Resume' : '⏸ Pause'}</Button>
          <select className="select" style={{ width: 220, padding: '7px 36px 7px 14px' }} value={client} onChange={(e) => setClient(e.target.value as ClientId | 'all')} aria-label="Filter by client">
            <option value="all">All clients</option>
            {CLIENTS.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
        <span className="small muted">{paused ? `Paused · ${events.length - paused.length} new event(s) waiting` : 'Live · newest first · showing up to 300'}</span>
      </div>
      {list.length === 0 ? <EmptyState icon="📭" title="No telemetry yet">Turn the Engine on and run an attack, or send a batch from the dispatcher.</EmptyState> : (
        <div className="table-wrap tall">
          <table className="tbl">
            <caption className="sr-only">Raw events</caption>
            <thead><tr><th>ID</th><th>Timestamp</th><th>Client</th><th>Source</th><th>Host</th><th>User</th><th>Process</th><th>Action</th><th>IP</th><th>Message / Command</th></tr></thead>
            <tbody>{list.map((e) => (
              <tr key={e.id}>
                <td className="mono nowrap">{e.id}{e.origin !== 'ingest-api' && e.origin !== 'dispatcher' && <div><span className="pill chip" style={{ fontSize: 10, padding: '1px 8px', marginTop: 4 }} title={`origin: ${e.origin}`}>Simulated</span></div>}</td>
                <td className="mono nowrap">{fmtTime(e.ts)}</td>
                <td><ClientBadge client={e.client} /></td>
                <td>{e.source}</td>
                <td className="mono">{e.host ?? '-'}</td>
                <td className="mono">{e.user ?? '-'}</td>
                <td className="mono">{e.process ?? '-'}</td>
                <td className="mono nowrap">{e.action}</td>
                <td className="mono nowrap">{e.ip ?? '-'}</td>
                <td className="cmd">{e.message}{e.domain ? ` [${e.domain}]` : ''}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function jsonError(text: string, err: Error): string {
  const m = /position (\d+)/.exec(err.message);
  const lc = /line (\d+) column (\d+)/.exec(err.message);
  if (lc) return `Invalid JSON at line ${lc[1]}, column ${lc[2]}: ${err.message.split(' in JSON')[0]}`;
  if (m) {
    const pos = Number(m[1]);
    const before = text.slice(0, pos);
    const line = before.split('\n').length;
    const col = pos - before.lastIndexOf('\n');
    return `Invalid JSON at line ${line}, column ${col}: ${err.message.split(' in JSON')[0]}`;
  }
  return `Invalid JSON: ${err.message}`;
}

function Dispatcher() {
  const api = useStore((s) => s.api);
  const gate = useEngineGate();
  const [text, setText] = useState(() => JSON.stringify(PRESETS[0].body(), null, 2));
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ status: number; body: unknown } | null>(null);
  const [busy, setBusy] = useState(false);

  const send = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      setError(jsonError(text, e as Error));
      return;
    }
    setError(null);
    const count = Array.isArray(parsed) ? parsed.length : Array.isArray((parsed as { events?: unknown[] })?.events) ? (parsed as { events: unknown[] }).events.length : 0;
    if (count > MAX_BATCH) setError(`This batch has ${count} events; the API limit is ${MAX_BATCH}. Expect a 413.`);
    setBusy(true);
    const res = await api('POST', '/api/ingest', { body: parsed, origin: 'dispatcher' });
    setBusy(false);
    setResult(res);
  };

  return (
    <div className="grid g2">
      <section className="card stack" aria-label="Event dispatcher">
        <div className="card-title" style={{ marginBottom: 0 }}><h3>Compose a batch</h3></div>
        <div className="stack" style={{ gap: 8 }}>
          <span className="label">Presets</span>
          <div className="row">
            {PRESETS.map((p) => (
              <Button key={p.name} variant="secondary" size="sm" onClick={() => { setText(JSON.stringify(p.body(), null, 2)); setError(null); setResult(null); }}>{p.name}</Button>
            ))}
          </div>
          <span className="small muted">{PRESETS.map((p) => `${p.name}: ${p.desc}`).join(' · ')}</span>
        </div>
        <label className="field">
          <span>Request body · <code>POST /api/ingest</code></span>
          <textarea className="textarea" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-invalid={!!error} aria-describedby="json-err" />
        </label>
        {error && <div id="json-err" className="banner bad small" role="alert">{error}</div>}
        <div className="row">
          <Button onClick={send} disabledReason={gate} busy={busy}>Send batch</Button>
          <span className="small muted">Required per event: client (meezan | shu | contour), source, action. Optional: ts, host, user, ip, domain, process, message, meta.</span>
        </div>
      </section>
      <section className="card stack" aria-label="API response" aria-live="polite">
        <div className="card-title" style={{ marginBottom: 0 }}><h3>Mock API response</h3>{result && <span className={`pill ${result.status < 300 ? 'st-executed' : 'sev-CRITICAL'}`}>{result.status}</span>}</div>
        {result ? <pre className="yaml" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{JSON.stringify(result.body, null, 2)}</pre>
          : <EmptyState icon="📨" title="Nothing sent yet">Pick a preset and press Send batch. The response from the in-browser API appears here, and the terminal logs every step.</EmptyState>}
      </section>
    </div>
  );
}
