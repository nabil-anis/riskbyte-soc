import { useState } from 'react';
import { useStore } from '../store/store';
import { parseLogText, type ParseResult } from '../engine/logparse';
import { MAX_BATCH } from '../engine/normalize';
import { Button } from './ui';

const MAX_FILE = 5 * 1024 * 1024;

/** Upload a real log file (auth.log, syslog, JSON, NDJSON) and ingest it through the API in batches. */
export function LogUpload() {
  const orgs = useStore((s) => s.data.orgs);
  const api = useStore((s) => s.api);
  const track = useStore((s) => s.track);
  const [org, setOrg] = useState(orgs.find((o) => o.platform)?.id ?? orgs[0]?.id ?? '');
  const [file, setFile] = useState<{ name: string; size: number; parsed: ParseResult } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ sent: number; total: number; alerts: number; done: boolean } | null>(null);

  const onFile = async (f: File | undefined) => {
    setError(null); setProgress(null); setFile(null);
    if (!f) return;
    if (f.size > MAX_FILE) { setError(`File is ${(f.size / 1048576).toFixed(1)} MB; the limit is 5 MB.`); return; }
    const parsed = parseLogText(await f.text(), org);
    track('selected log file', `${f.name} (${f.size} bytes, ${parsed.format}, ${parsed.events.length} events)`);
    if (!parsed.events.length) { setError(`No recognisable log lines in ${f.name}. Supported: syslog/auth.log lines, JSON array, {"events": [...]}, NDJSON.`); return; }
    setFile({ name: f.name, size: f.size, parsed });
  };

  const ingest = async () => {
    if (!file) return;
    const events = file.parsed.events.map((e) => ({ ...e, client: org }));
    let alerts = 0;
    setProgress({ sent: 0, total: events.length, alerts: 0, done: false });
    track('uploaded log file', `${file.name} → ${org}, ${events.length} events`);
    for (let i = 0; i < events.length; i += MAX_BATCH) {
      const chunk = events.slice(i, i + MAX_BATCH);
      const res = await api('POST', '/api/ingest', { body: { events: chunk }, origin: 'ingest-api' });
      if (res.status !== 200) { setError(`Batch ${i / MAX_BATCH + 1} rejected (${res.status}): ${JSON.stringify((res.body as { problems?: string[] }).problems ?? res.body).slice(0, 200)}`); break; }
      alerts += (res.body as { alertIds: string[] }).alertIds.length;
      setProgress({ sent: Math.min(events.length, i + chunk.length), total: events.length, alerts, done: false });
    }
    setProgress((p) => (p ? { ...p, done: true } : p));
  };

  const counts = file ? Object.entries(file.parsed.events.reduce<Record<string, number>>((m, e) => { const a = String(e.action); m[a] = (m[a] ?? 0) + 1; return m; }, {})) : [];

  return (
    <section className="panel">
      <div className="panel-head"><h3>Upload a real log file</h3><div className="right"><span className="small muted">auth.log · syslog · JSON · NDJSON · up to 5 MB</span></div></div>
      <div className="panel-body stack">
        <div className="row">
          <label className="field" style={{ minWidth: 220 }}><span>Organization</span>
            <select className="select" value={org} onChange={(e) => setOrg(e.target.value)} aria-label="Organization for uploaded logs">
              {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          </label>
          <label className="field grow"><span>Log file</span>
            <input className="input" type="file" accept=".log,.txt,.json,.ndjson,.jsonl,text/plain,application/json" onChange={(e) => onFile(e.target.files?.[0])} />
          </label>
        </div>
        <p className="small muted">Linux <code>/var/log/auth.log</code> or <code>journalctl -u ssh</code> output works directly: sshd failed/accepted logins, invalid users, sudo commands and new accounts are mapped to events, so a real brute-force in your logs fires rb-001. The file is parsed in your browser.</p>
        {file && (
          <div className="banner">
            <div className="grow small">
              <b>{file.name}</b> · {(file.size / 1024).toFixed(1)} KB · {file.parsed.format} · {file.parsed.events.length} events{file.parsed.skipped ? ` · ${file.parsed.skipped} lines skipped` : ''}
              <div className="muted">{counts.map(([a, n]) => `${a}: ${n}`).join(' · ')}</div>
            </div>
            <Button onClick={ingest} disabledReason={progress && !progress.done ? 'Ingesting…' : null}>Ingest {file.parsed.events.length} events</Button>
          </div>
        )}
        {progress && (
          <div className="stack" style={{ gap: 6 }}>
            <span className="small">{progress.sent} / {progress.total} events ingested · {progress.alerts} alert{progress.alerts === 1 ? '' : 's'} raised{progress.done ? ' · done' : '…'}</span>
            <div className="progress-line"><span style={{ width: `${(progress.sent / Math.max(1, progress.total)) * 100}%` }} /></div>
          </div>
        )}
        {error && <div className="banner bad small" role="alert">{error}</div>}
      </div>
    </section>
  );
}
