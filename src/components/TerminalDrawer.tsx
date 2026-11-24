import { useEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react';
import { useStore, effectiveKey } from '../store/store';
import { RULES } from '../data/rules';
import { TOKENS } from '../engine/auth';
import { copy } from './ui';

const HELP = [
  'help            list commands',
  'status          engine state, role, provider, counts, audit state',
  'rules           the 10 Sigma-style detection rules',
  'stats           totals and average processing time',
  'verify-audit    re-verify the SHA-256 audit chain',
  'clear           clear the screen',
  'reset           reset demo data (admin only, asks to confirm)',
  'engine on|off   start or stop the engine',
];

export function TerminalDrawer() {
  const open = useStore((s) => s.terminalOpen);
  const logs = useStore((s) => s.logs);
  const paused = useStore((s) => s.paused);
  const set = useStore((s) => s.set);
  const [height, setHeight] = useState(280);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [hIdx, setHIdx] = useState(-1);
  const [awaitingReset, setAwaitingReset] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!paused && bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [logs, paused, open]);

  useEffect(() => {
    document.documentElement.style.setProperty('--term-h', `${open ? height : 0}px`);
    document.body.style.paddingBottom = open ? `${height}px` : '';
  }, [open, height]);

  if (!open) return null;

  const echo = (text: string) => useStore.getState().log('INFO', text);
  const out = (lines: string[]) => lines.forEach((l) => echo(l));

  const run = async (raw: string) => {
    const cmd = raw.trim();
    const st = useStore.getState();
    st.log('INFO', `riskbyte> ${cmd}`);
    if (!cmd) return;
    setHistory((h) => [...h.filter((x) => x !== cmd), cmd].slice(-50));
    setHIdx(-1);
    if (awaitingReset) {
      setAwaitingReset(false);
      if (cmd === 'YES') {
        if (st.session?.role !== 'admin') return st.log('WARN', 'reset: forbidden (only the Administrator can reset demo data)');
        await st.resetDemo();
      } else st.log('INFO', 'reset cancelled');
      return;
    }
    const [c, arg] = cmd.split(/\s+/);
    switch (c) {
      case 'help': out(HELP); break;
      case 'status': {
        const s = st.data;
        out([
          `engine        ${st.engineOn ? 'on' : 'off'} (in-browser)`,
          `role          ${st.session?.role} (token ${st.session ? TOKENS[st.session.role] : '-'})`,
          `provider      ${effectiveKey(st.settings) ? `gemini (${st.settings.model})` : 'heuristic (no API key set)'}`,
          `events        ${s.events.length} stored / ${s.counters.totalIngested} ingested`,
          `alerts        ${s.alerts.length} (${s.alerts.filter((a) => a.status === 'triaged' || a.status === 'new').length} awaiting decision)`,
          `cases         ${s.cases.length} (${s.cases.filter((x) => x.status === 'open').length} open)`,
          `audit         ${s.audit.length} blocks, ${st.audit.intact ? 'chain intact' : `TAMPERED at block #${st.audit.brokenAt}`}`,
        ]);
        break;
      }
      case 'rules':
        out(RULES.map((r) => `${r.id}  ${r.severity.padEnd(8)} ${r.mitre.padEnd(10)} ${r.action.padEnd(15)} ${r.title}`));
        break;
      case 'stats': {
        const c2 = st.data.counters;
        out([
          `total ingested   ${c2.totalIngested}`,
          `batches          ${c2.batches}`,
          `alerts           ${st.data.alerts.length}`,
          `cases            ${st.data.cases.length}`,
          `avg processing   ${c2.batches ? (c2.totalMs / c2.batches).toFixed(1) : '0.0'} ms per batch (detection pipeline, excluding AI)`,
        ]);
        break;
      }
      case 'verify-audit': await st.verifyAudit(); break;
      case 'clear': st.clearLogs(); break;
      case 'reset':
        if (st.session?.role !== 'admin') { st.log('WARN', "reset: forbidden. Role '" + st.session?.role + "' cannot reset demo data"); break; }
        setAwaitingReset(true);
        st.log('WARN', 'This clears events, alerts, cases and the audit ledger. Type YES to confirm.');
        break;
      case 'engine':
        if (arg === 'on' || arg === 'off') await st.setEngine(arg === 'on');
        else st.log('INFO', 'usage: engine on | engine off');
        break;
      default:
        st.log('WARN', `command not found: ${c}. Type help.`);
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

  const startDrag = (e: PointerEvent<HTMLButtonElement>) => {
    const startY = e.clientY, startH = height;
    const move = (ev: globalThis.PointerEvent) => {
      const max = window.innerHeight * 0.7;
      setHeight(Math.round(Math.min(max, Math.max(160, startH + (startY - ev.clientY)))));
    };
    const up = () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  };

  return (
    <section className="terminal" style={{ height }} aria-label="Riskbyte terminal">
      <button type="button" className="term-handle" onPointerDown={startDrag} aria-label="Drag to resize terminal"
        onKeyDown={(e) => { if (e.key === 'ArrowUp') setHeight((h) => Math.min(window.innerHeight * 0.7, h + 20)); if (e.key === 'ArrowDown') setHeight((h) => Math.max(160, h - 20)); }} />
      <div className="term-head">
        <span className="title"><span className="mono" style={{ color: 'var(--coral)' }}>&gt;_</span> riskbyte engine log</span>
        <button type="button" className="term-btn" aria-pressed={paused} onClick={() => set({ paused: !paused })}>{paused ? 'Resume' : 'Pause'}</button>
        <button type="button" className="term-btn" onClick={() => useStore.getState().clearLogs()}>Clear</button>
        <button type="button" className="term-btn" onClick={() => copy(logs.map((l) => `${l.ts} ${l.level.padEnd(5)} ${l.text}`).join('\n')).then(() => useStore.getState().toast('Log copied'))}>Copy log</button>
        <button type="button" className="term-btn" onClick={() => set({ terminalOpen: false })} aria-label="Close terminal">Close ✕</button>
      </div>
      <div className="term-body" ref={bodyRef} role="log" aria-live="off">
        {logs.length === 0 && <div className="term-line" style={{ color: 'var(--muted-dark)' }}>No output yet. Turn the Engine on, or type <b>help</b>.</div>}
        {logs.map((l) => (
          <div key={l.id} className={`term-line ${l.text.startsWith('riskbyte> ') ? 'echo' : ''}`}>
            <span className="ts">{l.ts}</span><span className={`lvl lvl-${l.level}`}>{l.level}</span>{l.text}
          </div>
        ))}
      </div>
      <div className="term-input">
        <label htmlFor="term-cmd">{awaitingReset ? 'confirm>' : 'riskbyte>'}</label>
        <input id="term-cmd" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={onKey} autoComplete="off" spellCheck={false} placeholder={awaitingReset ? 'type YES to confirm' : 'type help'} />
      </div>
    </section>
  );
}
