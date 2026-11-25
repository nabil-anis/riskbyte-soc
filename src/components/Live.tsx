import { useEffect, useRef } from 'react';
import { useStore, aiMode, aiLabel } from '../store/store';
import { useTick } from './ui';

/** A compact, always-scrolling view of the pipeline log. */
export function LiveLog({ lines = 10, height = 240, title = 'Live pipeline' }: { lines?: number; height?: number; title?: string }) {
  const logs = useStore((s) => s.logs);
  const ref = useRef<HTMLDivElement>(null);
  const shown = logs.slice(-lines);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [logs]);
  return (
    <section className="livelog" aria-label={title}>
      <div className="livelog-head"><span className="pulse-dot" aria-hidden />{title}<span className="grow" /><span className="mono small">{logs.length} lines</span></div>
      <div className="livelog-body" ref={ref} style={{ height }} role="log" aria-live="off">
        {shown.map((l) => (
          <div key={l.id} className="term-line"><span className="ts">{l.ts}</span><span className={`lvl lvl-${l.level}`}>{l.level}</span>{l.text}</div>
        ))}
      </div>
    </section>
  );
}

export function useMonitorStats() {
  useTick(1000);
  const monitor = useStore((s) => s.monitor);
  const bootedAt = useStore((s) => s.bootedAt);
  const events = useStore((s) => s.data.events);
  const total = useStore((s) => s.data.counters.totalIngested);
  const now = Date.now();
  const perMin = events.filter((e) => now - Date.parse(e.ts) <= 60_000).length;
  const up = Math.floor((now - bootedAt) / 1000);
  const uptime = `${String(Math.floor(up / 3600)).padStart(2, '0')}:${String(Math.floor((up % 3600) / 60)).padStart(2, '0')}:${String(up % 60).padStart(2, '0')}`;
  const lastScan = monitor.lastScanAt ? Math.max(0, Math.round((now - monitor.lastScanAt) / 1000)) : null;
  return { perMin, uptime, lastScan, scans: monitor.scans, total };
}

/** "Monitoring 24/7 · last scan 2s ago" pill. */
export function MonitorPill() {
  const { lastScan } = useMonitorStats();
  return <span className="stat-pill live"><span className="d" />Monitoring 24/7{lastScan !== null ? ` · scan ${lastScan}s ago` : ' · starting'}</span>;
}

export function AiPill() {
  const st = useStore((s) => ({ settings: s.settings, serverAi: s.serverAi }));
  const mode = aiMode(st);
  return (
    <span className={`stat-pill ${mode === 'heuristic' ? 'warn' : ''}`} title={mode === 'server' ? 'Gemini via server-side GEMINI_API_KEY' : mode === 'browser' ? 'Gemini via key stored in this browser' : 'No Gemini key found; local heuristic model'}>
      <span className="d" />AI: {aiLabel(st)}
    </span>
  );
}
