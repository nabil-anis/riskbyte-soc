import { useEffect, useMemo, useRef, useState } from 'react';
import { useStore } from '../store/store';
import type { LogLevel, LogLine, LogSource } from '../engine/types';
import { Button } from './ui';

const SOURCES: (LogSource | 'all')[] = ['all', 'user', 'api', 'pipeline', 'agent', 'audit', 'simulator', 'system'];
const LEVELS: (LogLevel | 'all')[] = ['all', 'INFO', 'OK', 'WARN', 'ALERT', 'ERROR'];

/** SIEM-style live log viewer: every user action, API call, pipeline scan, agent step and ledger write. */
export function LogViewer() {
  const logs = useStore((s) => s.logs);
  const [src, setSrc] = useState<LogSource | 'all'>('all');
  const [lvl, setLvl] = useState<LogLevel | 'all'>('all');
  const [q, setQ] = useState('');
  const [frozen, setFrozen] = useState<LogLine[] | null>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const source = frozen ?? logs;

  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return source.filter((l) => (src === 'all' || l.src === src) && (lvl === 'all' || l.level === lvl) && (!needle || l.text.toLowerCase().includes(needle)));
  }, [source, src, lvl, q]);
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const l of logs) c[l.src ?? 'system'] = (c[l.src ?? 'system'] ?? 0) + 1;
    return c;
  }, [logs]);
  const perMin = logs.filter((l) => l.at && Date.now() - Date.parse(l.at) <= 60_000).length;

  useEffect(() => {
    if (!frozen && bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [list, frozen]);

  const exportLog = () => {
    const text = list.map((l) => `${l.at ?? l.ts} ${l.level.padEnd(5)} [${l.src ?? 'system'}] ${l.text}`).join('\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url; a.download = `riskbyte-logs-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.log`; a.click();
    URL.revokeObjectURL(url);
    useStore.getState().track('exported logs', `${list.length} lines`);
  };

  return (
    <section className="console logview" aria-label="Live logs">
      <div className="term-head">
        <span className="title"><span className="pulse-dot" aria-hidden /> live logs · {perMin}/min</span>
        <div className="log-filters" role="group" aria-label="Log source">
          {SOURCES.map((s) => (
            <button key={s} type="button" className="term-btn" aria-pressed={src === s} onClick={() => setSrc(s)}>
              {s}{s !== 'all' && counts[s] ? ` ${counts[s]}` : ''}
            </button>
          ))}
        </div>
      </div>
      <div className="term-head">
        <select className="log-select" value={lvl} onChange={(e) => setLvl(e.target.value as LogLevel | 'all')} aria-label="Level">
          {LEVELS.map((l) => <option key={l} value={l}>{l === 'all' ? 'all levels' : l}</option>)}
        </select>
        <input className="log-search" placeholder="Search logs…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search logs" />
        <span className="grow" />
        <button type="button" className="term-btn" aria-pressed={!!frozen} onClick={() => setFrozen(frozen ? null : [...logs])}>{frozen ? `Resume (${logs.length - frozen.length} new)` : 'Pause'}</button>
        <button type="button" className="term-btn" onClick={exportLog}>Export .log</button>
      </div>
      <div className="term-body" ref={bodyRef} role="log" aria-live="off">
        {list.length === 0 && <div className="term-line" style={{ color: 'var(--muted-dark)' }}>No log lines match.</div>}
        {list.map((l) => (
          <div key={l.id} className="term-line">
            <span className="ts">{l.ts}</span>
            <span className={`lvl lvl-${l.level}`}>{l.level}</span>
            <span className={`srcb src-${l.src ?? 'system'}`}>{l.src ?? 'system'}</span>
            {l.text}
          </div>
        ))}
      </div>
      <div className="term-input" style={{ justifyContent: 'space-between' }}>
        <span className="small" style={{ color: 'var(--muted-dark)' }}>{list.length} of {logs.length} lines · last 800 kept across reloads</span>
        <Button size="sm" variant="secondary" onClick={() => useStore.getState().enter('ingest', 'console')}>Open console</Button>
      </div>
    </section>
  );
}
