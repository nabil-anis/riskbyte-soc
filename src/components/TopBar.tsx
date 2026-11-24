import { useEffect, useRef, useState } from 'react';
import { useStore, ROLE_LABEL } from '../store/store';
import type { Role } from '../engine/types';
import { useTick } from './ui';

export function EngineToggle() {
  const on = useStore((s) => s.engineOn);
  const booting = useStore((s) => s.booting);
  const setEngine = useStore((s) => s.setEngine);
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-busy={booting}
      aria-label={`Engine ${on ? 'on' : 'off'}. Click to turn ${on ? 'off' : 'on'}.`}
      className={`engine-toggle ${on ? 'on' : ''}`}
      onClick={() => setEngine(!on)}
      title="The in-browser SOC engine. Turn it on to run attacks."
    >
      <span className="knob-track"><span className="knob">{booting && <span className="spinner" style={{ width: 12, height: 12, color: 'var(--coral)' }} />}</span></span>
      <span>Engine {booting ? 'starting…' : on ? 'ON' : 'OFF'}</span>
    </button>
  );
}

export function IslandPill() {
  useTick(500);
  const on = useStore((s) => s.engineOn);
  const island = useStore((s) => s.island);
  const active = island && island.until > Date.now() ? island : null;
  let cls = on ? 'live' : '';
  let text = on ? 'Riskbyte · Live SOC Engine' : 'Riskbyte · Engine off';
  if (active?.kind === 'critical') { cls = 'critical'; text = 'Riskbyte · CRITICAL alert'; }
  else if (active?.kind === 'switched') { cls = 'switched'; text = `Riskbyte · ${active.text ?? 'Switched role'}`; }
  return (
    <div className={`island ${cls}`} role="status" aria-live="polite">
      <span className="sdot" aria-hidden />
      <span>{text}</span>
    </div>
  );
}

const ROLE_INFO: Record<Role, string> = {
  analyst: 'Investigate, approve, dismiss',
  admin: 'Everything + audit tools and reset',
  ingest: 'Send logs only; cannot approve',
};

export function RoleBadge() {
  const role = useStore((s) => s.session!.role);
  const switchRole = useStore((s) => s.switchRole);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', esc); };
  }, [open]);
  return (
    <div className="menu-wrap" ref={ref}>
      <button type="button" className="icon-btn role-badge" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)} title="Switch role">
        <span aria-hidden>👤</span><span>{ROLE_LABEL[role]}</span><span aria-hidden>▾</span>
      </button>
      {open && (
        <div className="menu" role="menu" aria-label="Switch role">
          {(['analyst', 'admin', 'ingest'] as Role[]).map((r) => (
            <button key={r} role="menuitemradio" aria-checked={r === role} type="button" onClick={() => { setOpen(false); if (r !== role) switchRole(r); }}>
              <b>{r === role ? '● ' : ''}{ROLE_LABEL[r]}</b>
              <span>{ROLE_INFO[r]}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function TopBar() {
  const terminalOpen = useStore((s) => s.terminalOpen);
  const set = useStore((s) => s.set);
  const signOut = useStore((s) => s.signOut);
  const setTab = useStore((s) => s.setTab);
  const role = useStore((s) => s.session!.role);
  return (
    <header className="topbar">
      <div className="topbar-inner">
        <button type="button" className="wordmark" onClick={() => setTab(role === 'ingest' ? 'ingest' : role === 'admin' ? 'admin' : 'alerts')} aria-label="Riskbyte home">
          <span className="dot" aria-hidden />Riskbyte
        </button>
        <div className="island-wrap"><IslandPill /></div>
        <div className="top-actions">
          <EngineToggle />
          <button type="button" className="icon-btn" aria-pressed={terminalOpen} onClick={() => set({ terminalOpen: !terminalOpen })} title="Toggle terminal" aria-label="Toggle terminal">
            <span className="mono" aria-hidden>&gt;_</span><span className="txt">Terminal</span>
          </button>
          <button type="button" className="icon-btn" onClick={() => set({ guideOpen: true })} title="Demo Guide" aria-label="Open demo guide">
            <span aria-hidden>?</span><span className="txt">Guide</span>
          </button>
          <button type="button" className="icon-btn" onClick={() => set({ settingsOpen: true })} title="Settings" aria-label="Open settings">
            <span aria-hidden>⚙</span>
          </button>
          <RoleBadge />
          <button type="button" className="icon-btn" onClick={signOut} title="Sign out">Sign out</button>
        </div>
      </div>
    </header>
  );
}
