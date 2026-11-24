import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { useStore, effectiveKey } from '../store/store';
import { RULES } from '../data/rules';
import { copy } from './ui';

const HELP = [
  'help            list commands',
  'status          agent, provider, counts, ledger state',
  'rules           the 10 Sigma-style detection rules',
  'orgs            registered organizations',
  'stats           ingest totals and average pipeline time',
  'verify-audit    re-verify the SHA-256 audit chain',
  'clear           clear the screen',
];

/** Pipeline console: live engine log plus a small command line. No real shell, no eval. */
export function Console() {
  const logs = useStore((s) => s.logs);
  const [paused, setPaused] = useState(false);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [hIdx, setHIdx] = useState(-1);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!paused && bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [logs, paused]);

  const run = async (raw: string) => {
    const cmd = raw.trim();
    const st = useStore.getState();
    const out = (lines: string[]) => lines.forEach((l) => st.log('INFO', l));
    st.log('INFO', `riskbyte> ${cmd}`);
    if (!cmd) return;
    setHistory((h) => [...h.filter((x) => x !== cmd), cmd].slice(-50));
    setHIdx(-1);
    const d = st.data;
    switch (cmd.split(/\s+/)[0]) {
      case 'help': out(HELP); break;
      case 'status':
        out([
          'agent         online (in-browser)',
          `provider      ${effectiveKey(st.settings) ? `gemini (${st.settings.model})` : 'heuristic (no API key set)'}`,
          `policy        ${Object.entries(st.settings.policy.modes).map(([a, m]) => `${a}=${m}`).join(' ')}`,
          `orgs          ${d.orgs.length}`,
          `events        ${d.events.length} stored / ${d.counters.totalIngested} ingested`,
          `alerts        ${d.alerts.length} (${d.alerts.filter((a) => a.status === 'triaged' || a.status === 'new').length} awaiting decision)`,
          `incidents     ${d.cases.length} (${d.cases.filter((x) => x.status === 'open').length} open)`,
          `ledger        ${d.audit.length} blocks, ${st.audit.intact ? 'chain intact' : `TAMPERED at block #${st.audit.brokenAt}`}`,
        ]);
        break;
      case 'rules': out(RULES.map((r) => `${r.id}  ${r.severity.padEnd(8)} ${r.mitre.padEnd(10)} ${r.action.padEnd(15)} ${r.title}`)); break;
      case 'orgs': out(d.orgs.map((o) => `${o.id.padEnd(22)} ${o.name} (${o.sector})`)); break;
      case 'stats': {
        const c = d.counters;
        out([`total ingested   ${c.totalIngested}`, `batches          ${c.batches}`, `avg pipeline     ${c.batches ? (c.totalMs / c.batches).toFixed(1) : '0.0'} ms per batch (excluding AI)`]);
        break;
      }
      case 'verify-audit': await st.verifyAudit(); break;
      case 'clear': st.clearLogs(); break;
      default: st.log('WARN', `command not found: ${cmd.split(/\s+/)[0]}. Type help.`);
    }
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') { run(input); setInput(''); }
    else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!history.length) return;
      const i = hIdx < 0 ? history.length - 1 : Math.max(0, hIdx - 1);
      setHIdx(i); setInput(history[i]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (hIdx < 0) return;
      const i = hIdx + 1;
      if (i >= history.length) { setHIdx(-1); setInput(''); } else { setHIdx(i); setInput(history[i]); }
    }
  };

  return (
    <section className="console" aria-label="Pipeline console">
      <div className="term-head">
        <span className="title"><span className="mono" style={{ color: 'var(--coral)' }}>&gt;_</span> riskbyte pipeline</span>
        <button type="button" className="term-btn" aria-pressed={paused} onClick={() => setPaused(!paused)}>{paused ? 'Resume' : 'Pause'}</button>
        <button type="button" className="term-btn" onClick={() => useStore.getState().clearLogs()}>Clear</button>
        <button type="button" className="term-btn" onClick={() => copy(logs.map((l) => `${l.ts} ${l.level.padEnd(5)} ${l.text}`).join('\n')).then(() => useStore.getState().toast('Log copied'))}>Copy log</button>
      </div>
      <div className="term-body" ref={bodyRef} role="log">
        {logs.map((l) => (
          <div key={l.id} className={`term-line ${l.text.startsWith('riskbyte> ') ? 'echo' : ''}`}>
            <span className="ts">{l.ts}</span><span className={`lvl lvl-${l.level}`}>{l.level}</span>{l.text}
          </div>
        ))}
      </div>
      <div className="term-input">
        <label htmlFor="term-cmd">riskbyte&gt;</label>
        <input id="term-cmd" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={onKey} autoComplete="off" spellCheck={false} placeholder="type help" />
      </div>
    </section>
  );
}
